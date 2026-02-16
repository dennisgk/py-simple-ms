#!/usr/bin/env python3
import asyncio
import base64
import contextlib
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Dict, Optional, Tuple

import brotli
import websockets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from dotenv import load_dotenv


MAX_CHUNK_SIZE = 8 * 1024 * 1024


# ---------------------------
# Crypto helpers (PSK + HKDF + AEAD)
# ---------------------------
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def hkdf_32(key_material: bytes, salt: bytes, info: bytes) -> bytes:
    hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hk.derive(key_material)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def nonce_from_seq(seq: int) -> bytes:
    # 12-byte nonce: 4 zero bytes + 8-byte big-endian seq
    return (b"\x00" * 4) + seq.to_bytes(8, "big", signed=False)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def encode_message(msg: dict) -> bytes:
    raw = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    return brotli.compress(raw)


def decode_message(raw: Any) -> dict:
    if isinstance(raw, bytes):
        return json.loads(brotli.decompress(raw).decode("utf-8"))
    if isinstance(raw, str):
        return json.loads(raw)
    raise TypeError("unsupported websocket frame type")


@dataclass
class TunnelCrypto:
    # Directional keys:
    # server decrypts with c2s_key and encrypts with s2c_key
    c2s_key: bytes
    s2c_key: bytes
    dec_seq_expected: int = 0
    enc_seq: int = 0


@dataclass
class Session:
    session_id: str
    proc: subprocess.Popen
    last_used: float


@dataclass
class UploadState:
    upload_id: str
    final_path: str
    temp_path: str
    fh: BinaryIO
    next_seq: int
    bytes_written: int


@dataclass
class DownloadState:
    download_id: str
    fh: BinaryIO
    total_bytes: int


class ServerApp:
    def __init__(self, proxy_url: str, server_name: str, psk_hex: str, proxy_psk: str) -> None:
        self.proxy_url = proxy_url
        self.server_name = server_name
        self.psk = bytes.fromhex(psk_hex)
        self.proxy_psk = proxy_psk

        # tunnel_id -> crypto (after auth)
        self.crypto: Dict[str, TunnelCrypto] = {}
        # tunnel_id -> handshake state
        self.handshake: Dict[str, Dict[str, Any]] = {}
        # tunnel_id -> sessions
        self.sessions: Dict[str, Dict[str, Session]] = {}
        # tunnel_id -> upload_id -> upload state
        self.uploads: Dict[str, Dict[str, UploadState]] = {}
        # tunnel_id -> download_id -> download state
        self.downloads: Dict[str, Dict[str, DownloadState]] = {}
        # tunnel_id -> transfer_id -> RTC peer connection
        self.rtc_transfers: Dict[str, Dict[str, Any]] = {}

        self.ws: Optional[websockets.WebSocketClientProtocol] = None

    async def send(self, msg: dict) -> None:
        assert self.ws is not None
        await self.ws.send(encode_message(msg))

    async def send_tunnel_plain(self, tunnel_id: str, obj: dict) -> None:
        await self.send({"type": "tunnel_data", "tunnel_id": tunnel_id, "payload": {"type": "plain", "obj": obj}})

    async def send_tunnel_enc(self, tunnel_id: str, obj: dict) -> None:
        c = self.crypto[tunnel_id]
        aead = ChaCha20Poly1305(c.s2c_key)
        seq = c.enc_seq
        c.enc_seq += 1

        pt = json.dumps(obj).encode("utf-8")
        nonce = nonce_from_seq(seq)
        # AAD binds tunnel+seq to ciphertext
        aad = (tunnel_id + "|" + str(seq)).encode("utf-8")
        ct = aead.encrypt(nonce, pt, aad)

        payload = {"type": "enc", "seq": seq, "ct": b64e(ct)}
        await self.send({"type": "tunnel_data", "tunnel_id": tunnel_id, "payload": payload})

    def recv_tunnel_enc(self, tunnel_id: str, payload: dict) -> dict:
        c = self.crypto[tunnel_id]
        seq = int(payload["seq"])
        if seq != c.dec_seq_expected:
            raise ValueError(f"bad seq (expected {c.dec_seq_expected}, got {seq})")
        c.dec_seq_expected += 1

        aead = ChaCha20Poly1305(c.c2s_key)
        nonce = nonce_from_seq(seq)
        aad = (tunnel_id + "|" + str(seq)).encode("utf-8")
        pt = aead.decrypt(nonce, b64d(payload["ct"]), aad)
        return json.loads(pt.decode("utf-8"))

    # ---------------------------
    # pyenv helpers
    # ---------------------------
    def _run_pyenv(self, args, env: Optional[dict] = None) -> Tuple[int, str, str]:
        p = subprocess.run(
            ["pyenv", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        return p.returncode, p.stdout, p.stderr

    def list_virtualenvs(self) -> Dict[str, Any]:
        # Uses: pyenv virtualenvs --bare  (requires pyenv-virtualenv)
        rc, out, err = self._run_pyenv(["virtualenvs", "--bare"])
        if rc != 0:
            return {"ok": False, "error": err.strip() or "pyenv virtualenvs failed"}
        envs = [line.strip() for line in out.splitlines() if line.strip()]
        return {"ok": True, "envs": envs}

    def create_virtualenv(self, base_version: str, env_name: str) -> Dict[str, Any]:
        rc, out, err = self._run_pyenv(["virtualenv", base_version, env_name])
        return {"ok": rc == 0, "stdout": out, "stderr": err}

    def delete_virtualenv(self, env_name: str) -> Dict[str, Any]:
        rc, out, err = self._run_pyenv(["uninstall", "-f", env_name])
        return {"ok": rc == 0, "stdout": out, "stderr": err}

    # ---------------------------
    # file helpers
    # ---------------------------
    def write_file(self, path: str, data_b64: str) -> Dict[str, Any]:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        data = b64d(data_b64)
        with open(path, "wb") as f:
            f.write(data)
        return {"ok": True, "bytes": len(data)}

    def read_file(self, path: str) -> Dict[str, Any]:
        with open(path, "rb") as f:
            data = f.read()
        return {"ok": True, "data_b64": b64e(data), "bytes": len(data)}

    def file_put_begin(self, tunnel_id: str, path: str) -> Dict[str, Any]:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        upload_id = secrets.token_hex(8)
        temp_path = f"{path}.upload.{upload_id}.part"
        fh = open(temp_path, "wb")
        st = UploadState(upload_id=upload_id, final_path=path, temp_path=temp_path, fh=fh, next_seq=0, bytes_written=0)
        self.uploads.setdefault(tunnel_id, {})[upload_id] = st
        return {"ok": True, "upload_id": upload_id}

    def file_put_chunk(self, tunnel_id: str, upload_id: str, seq: int, data_b64: str) -> Dict[str, Any]:
        st = self.uploads.get(tunnel_id, {}).get(upload_id)
        if not st:
            return {"ok": False, "error": "no such upload"}
        if seq != st.next_seq:
            return {"ok": False, "error": f"bad seq (expected {st.next_seq}, got {seq})"}

        chunk = b64d(data_b64)
        st.fh.write(chunk)
        st.bytes_written += len(chunk)
        st.next_seq += 1
        return {"ok": True, "bytes": len(chunk), "next_seq": st.next_seq}

    def file_put_end(self, tunnel_id: str, upload_id: str) -> Dict[str, Any]:
        st = self.uploads.get(tunnel_id, {}).pop(upload_id, None)
        if not st:
            return {"ok": False, "error": "no such upload"}

        st.fh.flush()
        st.fh.close()
        os.replace(st.temp_path, st.final_path)
        return {"ok": True, "bytes": st.bytes_written}

    def file_put_abort(self, tunnel_id: str, upload_id: str) -> Dict[str, Any]:
        st = self.uploads.get(tunnel_id, {}).pop(upload_id, None)
        if not st:
            return {"ok": False, "error": "no such upload"}

        with contextlib.suppress(Exception):
            st.fh.close()
        with contextlib.suppress(Exception):
            os.remove(st.temp_path)
        return {"ok": True}

    def file_get_begin(self, tunnel_id: str, path: str) -> Dict[str, Any]:
        fh = open(path, "rb")
        total_bytes = os.path.getsize(path)
        download_id = secrets.token_hex(8)
        st = DownloadState(download_id=download_id, fh=fh, total_bytes=total_bytes)
        self.downloads.setdefault(tunnel_id, {})[download_id] = st
        return {"ok": True, "download_id": download_id, "bytes": total_bytes}

    def file_get_chunk(self, tunnel_id: str, download_id: str, chunk_size: int) -> Dict[str, Any]:
        st = self.downloads.get(tunnel_id, {}).get(download_id)
        if not st:
            return {"ok": False, "error": "no such download"}

        size = min(max(1, int(chunk_size)), MAX_CHUNK_SIZE)
        data = st.fh.read(size)
        done = len(data) == 0
        return {"ok": True, "data_b64": b64e(data), "bytes": len(data), "done": done}

    def file_get_end(self, tunnel_id: str, download_id: str) -> Dict[str, Any]:
        st = self.downloads.get(tunnel_id, {}).pop(download_id, None)
        if not st:
            return {"ok": False, "error": "no such download"}

        st.fh.close()
        return {"ok": True}

    def mount_tree_diff(self, base_path: str, files: list, prune: bool = False) -> Dict[str, Any]:
        base = Path(base_path).resolve()
        base.mkdir(parents=True, exist_ok=True)

        expected_rel_paths = set()
        needed = []
        invalid = []

        for item in files:
            rel_path = str(item.get("rel_path", ""))
            expected = str(item.get("sha256", ""))
            rel_parts = PurePosixPath(rel_path).parts
            if not rel_path or PurePosixPath(rel_path).is_absolute() or ".." in rel_parts:
                invalid.append(rel_path)
                continue
            expected_rel_paths.add(rel_path)

            dst = (base / Path(rel_path)).resolve()
            try:
                dst.relative_to(base)
            except ValueError:
                invalid.append(rel_path)
                continue

            if not dst.is_file():
                needed.append(rel_path)
                continue

            try:
                current = sha256_file(dst)
            except Exception:
                needed.append(rel_path)
                continue

            if current != expected:
                needed.append(rel_path)

        if invalid:
            return {"ok": False, "error": "invalid rel_path entries", "invalid": invalid}

        deleted = 0
        if prune:
            for path in base.rglob("*"):
                if not path.is_file():
                    continue
                rel = path.relative_to(base).as_posix()
                if rel not in expected_rel_paths:
                    with contextlib.suppress(Exception):
                        path.unlink()
                        deleted += 1

            # Cleanup empty directories after pruning extra files.
            for path in sorted(base.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                if path.is_dir():
                    with contextlib.suppress(Exception):
                        path.rmdir()

        return {"ok": True, "total": len(files), "needed": needed, "deleted": deleted}

    # ---------------------------
    # sessions
    # ---------------------------
    def start_session(self, tunnel_id: str, env_name: str, cwd: str) -> Dict[str, Any]:
        session_id = secrets.token_hex(8)
        os.makedirs(cwd, exist_ok=True)

        # Use PYENV_VERSION to choose env; run python worker with -u unbuffered
        env = os.environ.copy()
        env["PYENV_VERSION"] = env_name
        env.setdefault("PY_COLORS", "1")
        env.setdefault("FORCE_COLOR", "1")
        env.setdefault("CLICOLOR_FORCE", "1")
        env.setdefault("TERM", "xterm-256color")

        worker_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "session_worker.py")
        proc = subprocess.Popen(
            ["pyenv", "exec", "python", "-u", worker_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            env=env,
        )

        self.sessions.setdefault(tunnel_id, {})[session_id] = Session(session_id=session_id, proc=proc, last_used=time.time())
        return {"ok": True, "session_id": session_id}

    def stop_session(self, tunnel_id: str, session_id: str) -> Dict[str, Any]:
        sess = self.sessions.get(tunnel_id, {}).pop(session_id, None)
        if not sess:
            return {"ok": False, "error": "no such session"}
        with contextlib.suppress(Exception):
            sess.proc.terminate()
        with contextlib.suppress(Exception):
            sess.proc.kill()
        return {"ok": True}

    async def exec_in_session_stream(self, tunnel_id: str, session_id: str, code: str, req_id: str) -> Dict[str, Any]:
        sess = self.sessions.get(tunnel_id, {}).get(session_id)
        if not sess:
            return {"ok": False, "error": "no such session"}

        assert sess.proc.stdin and sess.proc.stdout
        sess.last_used = time.time()
        sess.proc.stdin.write(json.dumps({"type": "exec", "code": code}) + "\n")
        sess.proc.stdin.flush()

        # Stream events until final exec_result arrives.
        while True:
            line = sess.proc.stdout.readline()
            if not line:
                return {"ok": False, "error": "session died"}

            msg = json.loads(line)
            mtype = msg.get("type")

            if mtype == "stream":
                await self.send_tunnel_enc(
                    tunnel_id,
                    {
                        "type": "session_stream",
                        "req_id": req_id,
                        "session_id": session_id,
                        "stream": msg.get("stream"),
                        "data": msg.get("data", ""),
                    },
                )
                continue

            if mtype == "exec_result":
                return {"ok": True, "result": msg}

            if mtype == "error":
                return {"ok": False, "error": msg.get("error", "worker error"), "traceback": msg.get("traceback", "")}

            return {"ok": False, "error": f"unknown worker message type: {mtype}"}

    def cleanup_tunnel(self, tunnel_id: str) -> None:
        # Stop any sessions for this tunnel
        for sid in list(self.sessions.get(tunnel_id, {}).keys()):
            self.stop_session(tunnel_id, sid)
        self.sessions.pop(tunnel_id, None)

        for upload_id in list(self.uploads.get(tunnel_id, {}).keys()):
            self.file_put_abort(tunnel_id, upload_id)
        self.uploads.pop(tunnel_id, None)

        for download_id in list(self.downloads.get(tunnel_id, {}).keys()):
            with contextlib.suppress(Exception):
                self.file_get_end(tunnel_id, download_id)
        self.downloads.pop(tunnel_id, None)

        for transfer_id, pc in list(self.rtc_transfers.get(tunnel_id, {}).items()):
            with contextlib.suppress(Exception):
                asyncio.create_task(pc.close())
            self.rtc_transfers.get(tunnel_id, {}).pop(transfer_id, None)
        self.rtc_transfers.pop(tunnel_id, None)

        self.crypto.pop(tunnel_id, None)
        self.handshake.pop(tunnel_id, None)

    async def _wait_ice_complete(self, pc: Any, timeout: float = 8.0) -> None:
        start = asyncio.get_running_loop().time()
        while getattr(pc, "iceGatheringState", "") != "complete":
            if asyncio.get_running_loop().time() - start > timeout:
                break
            await asyncio.sleep(0.05)

    async def webrtc_transfer_open(self, tunnel_id: str, mode: str, path: str, chunk_size: int, offer_sdp: str, offer_type: str) -> Dict[str, Any]:
        try:
            from aiortc import RTCPeerConnection, RTCSessionDescription
        except Exception as e:
            return {"ok": False, "error": f"aiortc unavailable: {e}"}

        transfer_id = secrets.token_hex(8)
        pc = RTCPeerConnection()
        self.rtc_transfers.setdefault(tunnel_id, {})[transfer_id] = pc

        async def close_pc() -> None:
            with contextlib.suppress(Exception):
                await pc.close()
            self.rtc_transfers.get(tunnel_id, {}).pop(transfer_id, None)

        try:
            if mode == "put":
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                temp_path = f"{path}.rtc.{transfer_id}.part"
                state: Dict[str, Any] = {"fh": None, "bytes": 0}

                @pc.on("datachannel")
                def on_datachannel(channel: Any) -> None:
                    @channel.on("message")
                    def on_message(message: Any) -> None:
                        try:
                            if isinstance(message, str):
                                obj = json.loads(message)
                                mtype = obj.get("type")
                                if mtype == "meta":
                                    state["fh"] = open(temp_path, "wb")
                                elif mtype == "eof":
                                    fh = state.get("fh")
                                    if fh:
                                        fh.flush()
                                        fh.close()
                                        os.replace(temp_path, path)
                                    channel.send(json.dumps({"type": "ack", "ok": True, "bytes": state["bytes"]}))
                                    asyncio.create_task(close_pc())
                            else:
                                fh = state.get("fh")
                                if fh is not None:
                                    chunk = bytes(message)
                                    fh.write(chunk)
                                    state["bytes"] += len(chunk)
                        except Exception as e:
                            channel.send(json.dumps({"type": "ack", "ok": False, "error": str(e)}))
                            asyncio.create_task(close_pc())

            elif mode == "get":
                file_path = Path(path)
                if not file_path.exists() or not file_path.is_file():
                    await close_pc()
                    return {"ok": False, "error": f"file not found: {path}"}
                file_size = file_path.stat().st_size
                effective_chunk = min(max(1, int(chunk_size)), MAX_CHUNK_SIZE)
                state: Dict[str, Any] = {"started": False}

                @pc.on("datachannel")
                def on_datachannel(channel: Any) -> None:
                    @channel.on("message")
                    def on_message(message: Any) -> None:
                        if not isinstance(message, str):
                            return
                        try:
                            obj = json.loads(message)
                            mtype = obj.get("type")
                            if mtype == "ack":
                                asyncio.create_task(close_pc())
                                return
                            if mtype != "ready" or state["started"]:
                                return
                        except Exception:
                            return

                        async def send_file() -> None:
                            try:
                                channel.send(json.dumps({"type": "meta", "size": file_size}))
                                with file_path.open("rb") as f:
                                    while True:
                                        chunk = f.read(effective_chunk)
                                        if not chunk:
                                            break
                                        channel.send(chunk)
                                        while channel.bufferedAmount > (8 * 1024 * 1024):
                                            await asyncio.sleep(0.01)
                                channel.send(json.dumps({"type": "eof"}))
                            except Exception:
                                await close_pc()

                        state["started"] = True
                        asyncio.create_task(send_file())
            else:
                await close_pc()
                return {"ok": False, "error": f"invalid mode: {mode}"}

            await pc.setRemoteDescription(RTCSessionDescription(sdp=offer_sdp, type=offer_type))
            answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)
            await self._wait_ice_complete(pc)
            return {
                "ok": True,
                "transfer_id": transfer_id,
                "answer_sdp": pc.localDescription.sdp,
                "answer_type": pc.localDescription.type,
                "transport": "webrtc",
            }
        except Exception as e:
            await close_pc()
            return {"ok": False, "error": f"webrtc_transfer_open failed: {e}"}

    # ---------------------------
    # Protocol handling
    # ---------------------------
    async def handle_plain(self, tunnel_id: str, obj: dict) -> None:
        mtype = obj.get("type")

        if mtype == "auth_hello":
            client_nonce = b64d(obj["client_nonce_b64"])
            server_nonce = secrets.token_bytes(32)

            self.handshake[tunnel_id] = {
                "client_nonce": client_nonce,
                "server_nonce": server_nonce,
                "authed": False,
            }

            await self.send_tunnel_plain(
                tunnel_id,
                {
                    "type": "auth_challenge",
                    "server_nonce_b64": b64e(server_nonce),
                },
            )
            return

        if mtype == "auth_proof":
            st = self.handshake.get(tunnel_id)
            if not st:
                await self.send_tunnel_plain(tunnel_id, {"type": "auth_fail", "error": "no handshake state"})
                return

            expected = hmac_sha256(self.psk, b"auth" + st["client_nonce"] + st["server_nonce"])
            got = b64d(obj["hmac_b64"])
            if not secrets.compare_digest(expected, got):
                await self.send_tunnel_plain(tunnel_id, {"type": "auth_fail", "error": "bad proof"})
                return

            # Derive session keys
            salt = hmac_sha256(self.psk, b"salt" + st["client_nonce"] + st["server_nonce"])
            c2s = hkdf_32(self.psk, salt=salt, info=b"c2s")
            s2c = hkdf_32(self.psk, salt=salt, info=b"s2c")
            self.crypto[tunnel_id] = TunnelCrypto(c2s_key=c2s, s2c_key=s2c)

            st["authed"] = True
            await self.send_tunnel_plain(tunnel_id, {"type": "auth_ok"})
            return

        # Anything else before auth: ignore
        await self.send_tunnel_plain(tunnel_id, {"type": "error", "error": "unauthenticated"})

    async def handle_enc(self, tunnel_id: str, payload: dict) -> None:
        try:
            obj = self.recv_tunnel_enc(tunnel_id, payload)
        except Exception as e:
            await self.send_tunnel_plain(tunnel_id, {"type": "error", "error": f"decrypt_failed: {e}"})
            return

        cmd = obj.get("cmd")
        req_id = obj.get("req_id")

        async def reply(resp: dict) -> None:
            resp2 = {"req_id": req_id, **resp}
            await self.send_tunnel_enc(tunnel_id, resp2)

        try:
            if cmd == "pyenv_list":
                await reply(self.list_virtualenvs())
                return

            if cmd == "pyenv_create":
                base_version = str(obj["base_version"])
                env_name = str(obj["env_name"])
                await reply(self.create_virtualenv(base_version, env_name))
                return

            if cmd == "pyenv_delete":
                env_name = str(obj["env_name"])
                await reply(self.delete_virtualenv(env_name))
                return

            if cmd == "file_put":
                path = str(obj["path"])
                data_b64 = str(obj["data_b64"])
                await reply(self.write_file(path, data_b64))
                return

            if cmd == "file_get":
                path = str(obj["path"])
                await reply(self.read_file(path))
                return

            if cmd == "file_put_begin":
                await reply(self.file_put_begin(tunnel_id, str(obj["path"])))
                return

            if cmd == "file_put_chunk":
                await reply(
                    self.file_put_chunk(
                        tunnel_id,
                        str(obj["upload_id"]),
                        int(obj["seq"]),
                        str(obj["data_b64"]),
                    )
                )
                return

            if cmd == "file_put_end":
                await reply(self.file_put_end(tunnel_id, str(obj["upload_id"])))
                return

            if cmd == "file_put_abort":
                await reply(self.file_put_abort(tunnel_id, str(obj["upload_id"])))
                return

            if cmd == "file_get_begin":
                await reply(self.file_get_begin(tunnel_id, str(obj["path"])))
                return

            if cmd == "file_get_chunk":
                chunk_size = int(obj.get("chunk_size", 256 * 1024))
                await reply(self.file_get_chunk(tunnel_id, str(obj["download_id"]), chunk_size))
                return

            if cmd == "file_get_end":
                await reply(self.file_get_end(tunnel_id, str(obj["download_id"])))
                return

            if cmd == "mount_tree_diff":
                base_path = str(obj["base_path"])
                files = list(obj.get("files", []))
                prune = bool(obj.get("prune", False))
                await reply(self.mount_tree_diff(base_path, files, prune=prune))
                return

            if cmd == "webrtc_transfer_open":
                mode = str(obj.get("mode", ""))
                path = str(obj.get("path", ""))
                chunk_size = int(obj.get("chunk_size", 256 * 1024))
                offer_sdp = str(obj.get("offer_sdp", ""))
                offer_type = str(obj.get("offer_type", ""))
                await reply(await self.webrtc_transfer_open(tunnel_id, mode, path, chunk_size, offer_sdp, offer_type))
                return

            if cmd == "session_start":
                env_name = str(obj["env_name"])
                cwd = str(obj["cwd"])
                await reply(self.start_session(tunnel_id, env_name, cwd))
                return

            if cmd == "session_stop":
                session_id = str(obj["session_id"])
                await reply(self.stop_session(tunnel_id, session_id))
                return

            if cmd == "session_exec":
                session_id = str(obj["session_id"])
                code = str(obj["code"])
                await reply(await self.exec_in_session_stream(tunnel_id, session_id, code, str(req_id)))
                return

            await reply({"ok": False, "error": f"unknown cmd: {cmd}"})

        except Exception as e:
            await reply({"ok": False, "error": f"exception: {e}"})

    async def run(self) -> None:
        async with websockets.connect(self.proxy_url, ping_interval=30, ping_timeout=30, max_size=None) as ws:
            self.ws = ws
            await self.send({"type": "register_server", "name": self.server_name, "proxy_psk": self.proxy_psk})
            print(f"[server] registered as {self.server_name}")

            # Heartbeat task
            async def heartbeat() -> None:
                while True:
                    try:
                        await self.send({"type": "heartbeat"})
                    except Exception:
                        return
                    await asyncio.sleep(10)

            hb_task = asyncio.create_task(heartbeat())

            try:
                async for raw in ws:
                    msg = decode_message(raw)
                    mtype = msg.get("type")

                    if mtype == "registered":
                        continue

                    if mtype == "heartbeat_ack":
                        continue

                    if mtype == "tunnel_open":
                        tunnel_id = msg["tunnel_id"]
                        self.sessions.setdefault(tunnel_id, {})
                        self.uploads.setdefault(tunnel_id, {})
                        self.downloads.setdefault(tunnel_id, {})
                        print(f"[server] tunnel_open {tunnel_id} peer={msg.get('peer')}")
                        continue

                    if mtype == "tunnel_close":
                        tunnel_id = msg["tunnel_id"]
                        print(f"[server] tunnel_close {tunnel_id} reason={msg.get('reason')}")
                        self.cleanup_tunnel(tunnel_id)
                        continue

                    if mtype == "tunnel_data":
                        tunnel_id = msg["tunnel_id"]
                        payload = msg["payload"]

                        ptype = payload.get("type")
                        if ptype == "plain":
                            await self.handle_plain(tunnel_id, payload.get("obj", {}))
                        elif ptype == "enc":
                            if tunnel_id not in self.crypto:
                                await self.send_tunnel_plain(tunnel_id, {"type": "error", "error": "not authenticated"})
                            else:
                                await self.handle_enc(tunnel_id, payload)
                        else:
                            await self.send_tunnel_plain(tunnel_id, {"type": "error", "error": "unknown payload type"})
                        continue

            finally:
                hb_task.cancel()
                with contextlib.suppress(Exception):
                    await hb_task


def main() -> None:
    # Load server env vars from a local .env file if present.
    load_dotenv()

    # Example:
    #   export PROXY_URL=ws://127.0.0.1:8765
    #   export SERVER_NAME=mybox
    #   export PSK_HEX=...64 hex chars...
    proxy_url = os.environ.get("PROXY_URL", "ws://127.0.0.1:8765")
    server_name = os.environ.get("SERVER_NAME", "server-1")
    proxy_psk = os.environ.get("PROXY_PSK", "").strip()
    psk_hex = os.environ.get("PSK_HEX")
    if not proxy_psk:
        print("Set PROXY_PSK to the shared proxy access key.", file=sys.stderr)
        sys.exit(1)
    if not psk_hex or len(psk_hex) < 32:
        print("Set PSK_HEX to a hex-encoded shared key (e.g. 64 hex chars = 32 bytes).", file=sys.stderr)
        sys.exit(1)

    app = ServerApp(proxy_url, server_name, psk_hex, proxy_psk)
    asyncio.run(app.run())


if __name__ == "__main__":
    main()
