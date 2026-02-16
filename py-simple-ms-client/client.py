#!/usr/bin/env python3
import asyncio
import argparse
import base64
import contextlib
import json
import secrets
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional

import brotli
import websockets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


FILE_CHUNK_SIZE = 256 * 1024
FILE_CHUNK_THRESHOLD = 512 * 1024


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
    def __init__(self, proxy_url: str, server_name: str, psk_hex: str, client_id: str = "") -> None:
        self.proxy_url = proxy_url
        self.server_name = server_name
        self.psk = bytes.fromhex(psk_hex)
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
        self.ws = await websockets.connect(self.proxy_url, ping_interval=30, ping_timeout=30)
        await self._send({"type": "register_client", "client_id": self.client_id})
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

    # -------- convenience wrappers --------
    async def pyenv_list(self) -> dict:
        return await self.request("pyenv_list")

    async def pyenv_create(self, base_version: str, env_name: str) -> dict:
        return await self.request("pyenv_create", base_version=base_version, env_name=env_name)

    async def pyenv_delete(self, env_name: str) -> dict:
        return await self.request("pyenv_delete", env_name=env_name)

    async def file_put(self, path: str, data: bytes, chunk_size: int = FILE_CHUNK_SIZE) -> dict:
        if len(data) <= FILE_CHUNK_THRESHOLD:
            return await self.request("file_put", path=path, data_b64=b64e(data))

        start = await self.request("file_put_begin", path=path)
        if not start.get("ok"):
            return start

        upload_id = start["upload_id"]
        seq = 0
        for offset in range(0, len(data), chunk_size):
            chunk = data[offset:offset + chunk_size]
            resp = await self.request("file_put_chunk", upload_id=upload_id, seq=seq, data_b64=b64e(chunk))
            if not resp.get("ok"):
                await self.request("file_put_abort", upload_id=upload_id)
                return resp
            seq += 1

        return await self.request("file_put_end", upload_id=upload_id)

    async def file_get(self, path: str, chunk_size: int = FILE_CHUNK_SIZE) -> bytes:
        start = await self.request("file_get_begin", path=path)
        if not start.get("ok"):
            raise FileNotFoundError(start.get("error", "file_get_begin failed"))

        download_id = start["download_id"]
        chunks = bytearray()

        try:
            while True:
                resp = await self.request("file_get_chunk", download_id=download_id, chunk_size=chunk_size)
                if not resp.get("ok"):
                    raise IOError(resp.get("error", "file_get_chunk failed"))

                data_b64 = resp.get("data_b64", "")
                if data_b64:
                    chunks.extend(b64d(data_b64))

                if resp.get("done"):
                    break
        finally:
            await self.request("file_get_end", download_id=download_id)

        return bytes(chunks)

    async def session_start(self, env_name: str, cwd: str) -> dict:
        return await self.request("session_start", env_name=env_name, cwd=cwd)

    async def session_exec(self, session_id: str, code: str) -> dict:
        return await self.request("session_exec", session_id=session_id, code=code)

    async def session_stop(self, session_id: str) -> dict:
        return await self.request("session_stop", session_id=session_id)


# ---------------------------
# Example CLI usage
# ---------------------------
async def demo(proxy_url: str, server_name: str, psk_hex: str) -> None:
    c = RemoteServerClient(proxy_url=proxy_url, server_name=server_name, psk_hex=psk_hex)
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
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(demo(args.proxy_url, args.server_name, args.psk_hex))
