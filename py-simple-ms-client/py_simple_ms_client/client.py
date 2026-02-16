#!/usr/bin/env python3
import asyncio
import argparse
import base64
import contextlib
import hashlib
import json
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Optional, Union

import brotli
import websockets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


FILE_CHUNK_SIZE = 2 * 1024 * 1024
FILE_CHUNK_THRESHOLD = 2 * 1024 * 1024


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
    # client encrypts with c2s_key and decrypts with s2c_key
    c2s_key: bytes
    s2c_key: bytes
    enc_seq: int = 0
    dec_seq_expected: int = 0


class RemoteServerClient:
    def __init__(
        self,
        proxy_url: str,
        server_name: str,
        psk_hex: str,
        proxy_psk: str,
        client_id: str = "",
    ) -> None:
        self.proxy_url = proxy_url
        self.server_name = server_name
        self.psk = bytes.fromhex(psk_hex)
        self.proxy_psk = proxy_psk
        self.client_id = client_id or f"client-{secrets.token_hex(4)}"

        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.tunnel_id: Optional[str] = None
        self.crypto: Optional[TunnelCrypto] = None

        self._pending: Dict[str, asyncio.Future] = {}
        self._reader_task: Optional[asyncio.Task] = None

        # handshake state
        self._client_nonce: Optional[bytes] = None
        self._server_nonce: Optional[bytes] = None

    async def _send(self, msg: dict) -> None:
        assert self.ws is not None
        await self.ws.send(encode_message(msg))

    async def _send_tunnel_plain(self, obj: dict) -> None:
        assert self.tunnel_id is not None
        await self._send({"type": "tunnel_data", "tunnel_id": self.tunnel_id, "payload": {"type": "plain", "obj": obj}})

    async def _send_tunnel_enc(self, obj: dict) -> None:
        assert self.tunnel_id is not None
        assert self.crypto is not None

        c = self.crypto
        aead = ChaCha20Poly1305(c.c2s_key)
        seq = c.enc_seq
        c.enc_seq += 1

        pt = json.dumps(obj).encode("utf-8")
        nonce = nonce_from_seq(seq)
        aad = (self.tunnel_id + "|" + str(seq)).encode("utf-8")
        ct = aead.encrypt(nonce, pt, aad)

        payload = {"type": "enc", "seq": seq, "ct": b64e(ct)}
        await self._send({"type": "tunnel_data", "tunnel_id": self.tunnel_id, "payload": payload})

    def _recv_tunnel_enc(self, payload: dict) -> dict:
        assert self.tunnel_id is not None
        assert self.crypto is not None
        c = self.crypto

        seq = int(payload["seq"])
        if seq != c.dec_seq_expected:
            raise ValueError(f"bad seq (expected {c.dec_seq_expected}, got {seq})")
        c.dec_seq_expected += 1

        aead = ChaCha20Poly1305(c.s2c_key)
        nonce = nonce_from_seq(seq)
        aad = (self.tunnel_id + "|" + str(seq)).encode("utf-8")
        pt = aead.decrypt(nonce, b64d(payload["ct"]), aad)
        return json.loads(pt.decode("utf-8"))

    async def _reader(self) -> None:
        assert self.ws is not None
        async for raw in self.ws:
            msg = decode_message(raw)
            mtype = msg.get("type")

            if mtype == "registered":
                continue

            if mtype == "tunnel_open":
                self.tunnel_id = msg["tunnel_id"]
                # start auth handshake immediately
                self._client_nonce = secrets.token_bytes(32)
                await self._send_tunnel_plain({"type": "auth_hello", "client_nonce_b64": b64e(self._client_nonce)})
                continue

            if mtype == "tunnel_close":
                # reject all pending
                for fut in self._pending.values():
                    if not fut.done():
                        fut.set_exception(ConnectionError("tunnel closed"))
                self._pending.clear()
                return

            if mtype == "tunnel_data":
                payload = msg["payload"]
                ptype = payload.get("type")

                if ptype == "plain":
                    obj = payload.get("obj", {})
                    if obj.get("type") == "auth_challenge":
                        self._server_nonce = b64d(obj["server_nonce_b64"])
                        proof = hmac_sha256(self.psk, b"auth" + self._client_nonce + self._server_nonce)
                        await self._send_tunnel_plain({"type": "auth_proof", "hmac_b64": b64e(proof)})
                    elif obj.get("type") == "auth_ok":
                        # derive session keys
                        salt = hmac_sha256(self.psk, b"salt" + self._client_nonce + self._server_nonce)
                        c2s = hkdf_32(self.psk, salt=salt, info=b"c2s")
                        s2c = hkdf_32(self.psk, salt=salt, info=b"s2c")
                        self.crypto = TunnelCrypto(c2s_key=c2s, s2c_key=s2c)
                        print("[client] authenticated, encryption ON")
                    elif obj.get("type") == "auth_fail":
                        raise PermissionError(obj.get("error", "auth failed"))
                    continue

                if ptype == "enc":
                    if not self.crypto:
                        continue
                    obj = self._recv_tunnel_enc(payload)
                    if obj.get("type") == "session_stream":
                        stream_name = obj.get("stream")
                        data = str(obj.get("data", ""))
                        # Some terminals/UIs don't render ANSI colors on stderr.
                        if stream_name == "stderr" and "\x1b[" in data:
                            out = sys.stdout
                        else:
                            out = sys.stderr if stream_name == "stderr" else sys.stdout
                        out.write(data)
                        out.flush()
                        continue

                    req_id = obj.get("req_id")
                    if req_id and req_id in self._pending:
                        fut = self._pending.pop(req_id)
                        if not fut.done():
                            fut.set_result(obj)
                    continue

    async def connect(self) -> None:
        self.ws = await websockets.connect(self.proxy_url, ping_interval=30, ping_timeout=30, max_size=None)
        await self._send({"type": "register_client", "client_id": self.client_id, "proxy_psk": self.proxy_psk})
        self._reader_task = asyncio.create_task(self._reader())
        await self._send({"type": "client_connect", "server_name": self.server_name})

        # Wait until crypto is set (auth complete)
        while self.crypto is None:
            await asyncio.sleep(0.05)

    async def close(self) -> None:
        if self.ws and self.tunnel_id:
            with contextlib.suppress(Exception):
                await self._send({"type": "tunnel_close", "tunnel_id": self.tunnel_id})
        if self.ws:
            await self.ws.close()
        if self._reader_task:
            self._reader_task.cancel()

    async def request(self, cmd: str, **kwargs: Any) -> dict:
        if not self.crypto or not self.tunnel_id:
            raise RuntimeError("not connected/authenticated")

        req_id = secrets.token_hex(8)
        fut = asyncio.get_running_loop().create_future()
        self._pending[req_id] = fut

        await self._send_tunnel_enc({"req_id": req_id, "cmd": cmd, **kwargs})
        return await fut

    async def _wait_ice_complete(self, pc: Any, timeout: float = 8.0) -> None:
        start = asyncio.get_running_loop().time()
        while getattr(pc, "iceGatheringState", "") != "complete":
            if asyncio.get_running_loop().time() - start > timeout:
                break
            await asyncio.sleep(0.05)

    async def _webrtc_open_transfer(self, mode: str, remote_path: str, chunk_size: int) -> tuple:
        try:
            from aiortc import RTCPeerConnection, RTCSessionDescription
        except Exception as e:
            raise RuntimeError(f"aiortc unavailable: {e}") from e

        pc = RTCPeerConnection()
        channel = pc.createDataChannel("file")
        open_fut = asyncio.get_running_loop().create_future()
        msg_q: asyncio.Queue = asyncio.Queue()

        @channel.on("open")
        def _on_open() -> None:
            if not open_fut.done():
                open_fut.set_result(True)

        @channel.on("message")
        def _on_message(message: Any) -> None:
            msg_q.put_nowait(message)

        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        await self._wait_ice_complete(pc)

        resp = await self.request(
            "webrtc_transfer_open",
            mode=mode,
            path=remote_path,
            chunk_size=chunk_size,
            offer_sdp=pc.localDescription.sdp,
            offer_type=pc.localDescription.type,
        )
        if not resp.get("ok"):
            await pc.close()
            raise RuntimeError(resp.get("error", "webrtc open failed"))

        answer = RTCSessionDescription(sdp=str(resp["answer_sdp"]), type=str(resp["answer_type"]))
        await pc.setRemoteDescription(answer)
        await asyncio.wait_for(open_fut, timeout=10.0)
        return pc, channel, msg_q

    async def _webrtc_file_put(self, remote_path: str, data: Union[bytes, str, Path], chunk_size: int) -> dict:
        if isinstance(data, bytes):
            total_size = len(data)

            def _iter_chunks() -> Any:
                for i in range(0, len(data), chunk_size):
                    yield data[i:i + chunk_size]
        else:
            local_path = Path(data)
            if not local_path.exists() or not local_path.is_file():
                return {"ok": False, "error": f"local source file not found: {local_path}"}
            total_size = local_path.stat().st_size

            def _iter_chunks() -> Any:
                with local_path.open("rb") as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        yield chunk

        pc, channel, msg_q = await self._webrtc_open_transfer("put", remote_path, chunk_size)
        try:
            channel.send(json.dumps({"type": "meta", "size": total_size}))
            uploaded = 0
            for chunk in _iter_chunks():
                channel.send(chunk)
                uploaded += len(chunk)
                self._print_progress(f"file_put {remote_path} (webrtc)", uploaded, total_size)
                while channel.bufferedAmount > (8 * 1024 * 1024):
                    await asyncio.sleep(0.01)
            channel.send(json.dumps({"type": "eof"}))
            self._end_progress()

            while True:
                msg = await asyncio.wait_for(msg_q.get(), timeout=20.0)
                if isinstance(msg, str):
                    obj = json.loads(msg)
                    if obj.get("type") == "ack":
                        return {"ok": bool(obj.get("ok", False)), "bytes": int(obj.get("bytes", 0)), "transport": "webrtc"}
        finally:
            await pc.close()

    async def _webrtc_file_get(
        self,
        remote_path: str,
        save_to: Optional[Union[str, Path]],
        chunk_size: int,
    ) -> Union[bytes, dict]:
        pc, channel, msg_q = await self._webrtc_open_transfer("get", remote_path, chunk_size)
        out_path = Path(save_to) if save_to is not None else None
        out_f = None
        chunks = bytearray() if out_path is None else None
        total_size = 0
        written = 0

        try:
            if out_path is not None:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_f = out_path.open("wb")

            channel.send(json.dumps({"type": "ready"}))
            while True:
                msg = await asyncio.wait_for(msg_q.get(), timeout=30.0)
                if isinstance(msg, str):
                    obj = json.loads(msg)
                    mtype = obj.get("type")
                    if mtype == "meta":
                        total_size = int(obj.get("size", 0))
                        continue
                    if mtype == "eof":
                        channel.send(json.dumps({"type": "ack", "ok": True, "bytes": written}))
                        break
                    continue

                chunk = bytes(msg)
                written += len(chunk)
                if out_f is not None:
                    out_f.write(chunk)
                else:
                    assert chunks is not None
                    chunks.extend(chunk)
                self._print_progress(f"file_get {remote_path} (webrtc)", written, total_size)

            self._end_progress()
        finally:
            if out_f is not None:
                out_f.close()
            await pc.close()

        if out_path is not None:
            return {"ok": True, "path": str(out_path), "bytes": written, "transport": "webrtc"}
        assert chunks is not None
        return bytes(chunks)

    @staticmethod
    def _fmt_bytes(n: int) -> str:
        units = ["B", "KB", "MB", "GB", "TB"]
        value = float(n)
        idx = 0
        while value >= 1024 and idx < len(units) - 1:
            value /= 1024.0
            idx += 1
        if idx == 0:
            return f"{int(value)}{units[idx]}"
        return f"{value:.1f}{units[idx]}"

    def _print_progress(self, label: str, current: int, total: int) -> None:
        if total > 0:
            pct = (current / total) * 100
            line = f"\r{label}: {pct:6.2f}% ({self._fmt_bytes(current)}/{self._fmt_bytes(total)})"
        else:
            line = f"\r{label}: {self._fmt_bytes(current)}"
        sys.stdout.write(line)
        sys.stdout.flush()

    @staticmethod
    def _end_progress() -> None:
        sys.stdout.write("\n")
        sys.stdout.flush()

    # -------- convenience wrappers --------
    async def pyenv_list(self) -> dict:
        return await self.request("pyenv_list")

    async def pyenv_create(self, base_version: str, env_name: str) -> dict:
        return await self.request("pyenv_create", base_version=base_version, env_name=env_name)

    async def pyenv_delete(self, env_name: str) -> dict:
        return await self.request("pyenv_delete", env_name=env_name)

    async def file_put(
        self,
        path: str,
        data: Union[bytes, str, Path],
        chunk_size: int = FILE_CHUNK_SIZE,
        transfer_mode: str = "ws",
    ) -> dict:
        if transfer_mode == "webrtc":
            try:
                return await self._webrtc_file_put(path, data, chunk_size)
            except Exception as e:
                print(f"[client] webrtc file_put fallback to ws: {e}", file=sys.stderr)

        # bytes -> upload content directly.
        # str/Path -> treated as a local file path to upload.
        if isinstance(data, bytes):
            total_size = len(data)
            if len(data) <= FILE_CHUNK_THRESHOLD:
                resp = await self.request("file_put", path=path, data_b64=b64e(data))
                self._print_progress(f"file_put {path}", total_size, total_size)
                self._end_progress()
                return resp

            start = await self.request("file_put_begin", path=path)
            if not start.get("ok"):
                return start

            upload_id = start["upload_id"]
            seq = 0
            uploaded = 0
            for offset in range(0, len(data), chunk_size):
                chunk = data[offset:offset + chunk_size]
                resp = await self.request("file_put_chunk", upload_id=upload_id, seq=seq, data_b64=b64e(chunk))
                if not resp.get("ok"):
                    await self.request("file_put_abort", upload_id=upload_id)
                    self._end_progress()
                    return resp
                seq += 1
                uploaded += len(chunk)
                self._print_progress(f"file_put {path}", uploaded, total_size)
            self._end_progress()
            return await self.request("file_put_end", upload_id=upload_id)

        local_path = Path(data)
        if not local_path.exists() or not local_path.is_file():
            return {"ok": False, "error": f"local source file not found: {local_path}"}

        file_size = local_path.stat().st_size
        if file_size <= FILE_CHUNK_THRESHOLD:
            resp = await self.request("file_put", path=path, data_b64=b64e(local_path.read_bytes()))
            self._print_progress(f"file_put {path}", file_size, file_size)
            self._end_progress()
            return resp

        start = await self.request("file_put_begin", path=path)
        if not start.get("ok"):
            return start

        upload_id = start["upload_id"]
        seq = 0
        uploaded = 0
        with local_path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                resp = await self.request("file_put_chunk", upload_id=upload_id, seq=seq, data_b64=b64e(chunk))
                if not resp.get("ok"):
                    await self.request("file_put_abort", upload_id=upload_id)
                    self._end_progress()
                    return resp
                seq += 1
                uploaded += len(chunk)
                self._print_progress(f"file_put {path}", uploaded, file_size)
        self._end_progress()
        return await self.request("file_put_end", upload_id=upload_id)

    async def file_get(
        self,
        path: str,
        save_to: Optional[Union[str, Path]] = None,
        chunk_size: int = FILE_CHUNK_SIZE,
        transfer_mode: str = "ws",
    ) -> Union[bytes, dict]:
        if transfer_mode == "webrtc":
            try:
                return await self._webrtc_file_get(path, save_to, chunk_size)
            except Exception as e:
                print(f"[client] webrtc file_get fallback to ws: {e}", file=sys.stderr)

        start = await self.request("file_get_begin", path=path)
        if not start.get("ok"):
            raise FileNotFoundError(start.get("error", "file_get_begin failed"))

        download_id = start["download_id"]
        total_size = int(start.get("bytes", 0))
        written = 0
        chunks = bytearray() if save_to is None else None
        out_path = Path(save_to) if save_to is not None else None
        out_f = None

        try:
            if out_path is not None:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_f = out_path.open("wb")

            while True:
                resp = await self.request("file_get_chunk", download_id=download_id, chunk_size=chunk_size)
                if not resp.get("ok"):
                    raise IOError(resp.get("error", "file_get_chunk failed"))

                data_b64 = resp.get("data_b64", "")
                if data_b64:
                    chunk = b64d(data_b64)
                    written += len(chunk)
                    if out_f is not None:
                        out_f.write(chunk)
                    else:
                        assert chunks is not None
                        chunks.extend(chunk)
                    self._print_progress(f"file_get {path}", written, total_size)

                if resp.get("done"):
                    break
        finally:
            if out_f is not None:
                out_f.close()
            await self.request("file_get_end", download_id=download_id)
            self._end_progress()

        if out_path is not None:
            return {"ok": True, "path": str(out_path), "bytes": written}
        assert chunks is not None
        return bytes(chunks)

    async def session_start(self, env_name: str, cwd: str) -> dict:
        return await self.request("session_start", env_name=env_name, cwd=cwd)

    async def session_exec(self, session_id: str, code: str) -> dict:
        return await self.request("session_exec", session_id=session_id, code=code)

    async def session_stop(self, session_id: str) -> dict:
        return await self.request("session_stop", session_id=session_id)

    async def mount_tree(
        self,
        server_path: str,
        local_path: Union[str, Path],
        mount_file: Optional[Callable[[str], bool]] = None,
        chunk_size: int = FILE_CHUNK_SIZE,
        transfer_mode: str = "ws",
    ) -> dict:
        local_path_obj = Path(local_path)
        local_root = local_path_obj.resolve()
        if not local_root.exists() or not local_root.is_dir():
            return {"ok": False, "error": f"local path is not a directory: {local_path}"}

        target_base = server_path
        if not local_path_obj.is_absolute():
            local_dir_name = local_path_obj.name
            if local_dir_name:
                target_base = str(PurePosixPath(server_path) / local_dir_name)

        manifest = []
        file_map: Dict[str, Path] = {}

        for path in local_root.rglob("*"):
            if not path.is_file():
                continue

            path_str = str(path)
            if mount_file and not mount_file(path_str):
                continue

            rel_path = path.relative_to(local_root).as_posix()
            file_map[rel_path] = path
            manifest.append(
                {
                    "rel_path": rel_path,
                    "sha256": sha256_file(path),
                    "size": path.stat().st_size,
                }
            )
            if len(manifest) % 50 == 0:
                self._print_progress("mount_tree scan files", len(manifest), 0)

        if manifest:
            self._print_progress("mount_tree scan files", len(manifest), len(manifest))
            self._end_progress()

        diff = await self.request("mount_tree_diff", base_path=target_base, files=manifest, prune=True)
        if not diff.get("ok"):
            return diff

        needed = diff.get("needed", [])
        deleted = int(diff.get("deleted", 0))
        uploaded = 0
        needed_total = len(needed)

        for idx, rel_path in enumerate(needed, start=1):
            src = file_map.get(rel_path)
            if src is None:
                return {"ok": False, "error": f"server requested unknown file: {rel_path}"}

            dst = str(PurePosixPath(target_base) / rel_path)
            resp = await self.file_put(dst, src, chunk_size=chunk_size, transfer_mode=transfer_mode)
            if not resp.get("ok"):
                return {"ok": False, "error": f"failed uploading {rel_path}", "upload_error": resp}
            uploaded += 1
            self._print_progress("mount_tree upload files", idx, needed_total)

        if needed_total:
            self._end_progress()

        return {
            "ok": True,
            "target_base": target_base,
            "scanned": len(manifest),
            "needed": len(needed),
            "uploaded": uploaded,
            "deleted": deleted,
        }


# ---------------------------
# Example CLI usage
# ---------------------------
async def demo(proxy_url: str, server_name: str, psk_hex: str, proxy_psk: str) -> None:
    c = RemoteServerClient(proxy_url=proxy_url, server_name=server_name, psk_hex=psk_hex, proxy_psk=proxy_psk)
    await c.connect()

    print(await c.pyenv_list())

    # Start session example (replace env/cwd)
    # s = await c.session_start(env_name="myenv", cwd="/tmp/myproj")
    # sid = s["session_id"]
    # r = await c.session_exec(sid, "print('hello from session')\nx=2+2\nprint(x)")
    # print(r)
    # await c.session_stop(sid)

    await c.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="py-simple-ms client")
    parser.add_argument("--proxy-url", required=True, help="Proxy websocket URL, e.g. ws://127.0.0.1:8765")
    parser.add_argument("--server-name", required=True, help="Registered server name to connect to")
    parser.add_argument("--psk-hex", required=True, help="Hex-encoded pre-shared key")
    parser.add_argument("--proxy-psk", required=True, help="Shared proxy access key")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asyncio.run(demo(args.proxy_url, args.server_name, args.psk_hex, args.proxy_psk))


if __name__ == "__main__":
    main()
