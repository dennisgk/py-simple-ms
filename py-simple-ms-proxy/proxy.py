#!/usr/bin/env python3
import asyncio
import json
import os
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional

import brotli
import websockets
from websockets.server import WebSocketServerProtocol


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
class Peer:
    ws: WebSocketServerProtocol
    kind: str  # "server" or "client"
    name: str  # server_name or client_id


@dataclass
class Tunnel:
    tunnel_id: str
    client: Peer
    server: Peer


class Proxy:
    def __init__(self, proxy_psk: str) -> None:
        self.proxy_psk = proxy_psk
        self.servers_by_name: Dict[str, Peer] = {}
        self.clients_by_ws: Dict[WebSocketServerProtocol, Peer] = {}
        self.tunnels: Dict[str, Tunnel] = {}

    async def _send(self, ws: WebSocketServerProtocol, msg: dict) -> None:
        await ws.send(encode_message(msg))

    async def _close_tunnel(self, tunnel_id: str, reason: str) -> None:
        t = self.tunnels.pop(tunnel_id, None)
        if not t:
            return
        # Notify both ends; they can cleanup their own resources.
        for peer in (t.client, t.server):
            try:
                await self._send(peer.ws, {"type": "tunnel_close", "tunnel_id": tunnel_id, "reason": reason})
            except Exception:
                pass

    async def handler(self, ws: WebSocketServerProtocol) -> None:
        peer: Optional[Peer] = None
        try:
            async for raw in ws:
                msg = decode_message(raw)
                mtype = msg.get("type")

                if mtype == "register_server":
                    if str(msg.get("proxy_psk", "")) != self.proxy_psk:
                        await self._send(ws, {"type": "error", "error": "invalid proxy_psk"})
                        await ws.close(code=1008, reason="invalid proxy_psk")
                        return
                    name = str(msg.get("name", "")).strip()
                    if not name:
                        await self._send(ws, {"type": "error", "error": "missing server name"})
                        continue
                    # Replace existing server registration if any
                    peer = Peer(ws=ws, kind="server", name=name)
                    self.servers_by_name[name] = peer
                    await self._send(ws, {"type": "registered", "name": name})
                    continue

                if mtype == "register_client":
                    if str(msg.get("proxy_psk", "")) != self.proxy_psk:
                        await self._send(ws, {"type": "error", "error": "invalid proxy_psk"})
                        await ws.close(code=1008, reason="invalid proxy_psk")
                        return
                    client_id = str(msg.get("client_id", "")).strip() or f"client-{secrets.token_hex(4)}"
                    peer = Peer(ws=ws, kind="client", name=client_id)
                    self.clients_by_ws[ws] = peer
                    await self._send(ws, {"type": "registered", "client_id": client_id})
                    continue

                if mtype == "heartbeat":
                    # Simple keepalive: reply
                    await self._send(ws, {"type": "heartbeat_ack"})
                    continue

                if mtype == "client_connect":
                    if not peer or peer.kind != "client":
                        await self._send(ws, {"type": "error", "error": "register_client first"})
                        continue
                    server_name = str(msg.get("server_name", "")).strip()
                    srv = self.servers_by_name.get(server_name)
                    if not srv:
                        await self._send(ws, {"type": "error", "error": f"server not found: {server_name}"})
                        continue

                    tunnel_id = secrets.token_hex(12)
                    t = Tunnel(tunnel_id=tunnel_id, client=peer, server=srv)
                    self.tunnels[tunnel_id] = t

                    # Tell both ends tunnel is open
                    await self._send(peer.ws, {"type": "tunnel_open", "tunnel_id": tunnel_id, "peer": server_name})
                    await self._send(srv.ws, {"type": "tunnel_open", "tunnel_id": tunnel_id, "peer": peer.name})
                    continue

                if mtype == "tunnel_data":
                    tunnel_id = str(msg.get("tunnel_id", ""))
                    payload = msg.get("payload")
                    t = self.tunnels.get(tunnel_id)
                    if not t:
                        await self._send(ws, {"type": "error", "error": f"unknown tunnel_id: {tunnel_id}"})
                        continue

                    # Forward to the other side. Proxy does NOT inspect payload.
                    if ws == t.client.ws:
                        await self._send(t.server.ws, {"type": "tunnel_data", "tunnel_id": tunnel_id, "payload": payload})
                    elif ws == t.server.ws:
                        await self._send(t.client.ws, {"type": "tunnel_data", "tunnel_id": tunnel_id, "payload": payload})
                    else:
                        await self._send(ws, {"type": "error", "error": "ws not part of tunnel"})
                    continue

                if mtype == "tunnel_close":
                    tunnel_id = str(msg.get("tunnel_id", ""))
                    await self._close_tunnel(tunnel_id, "closed_by_peer")
                    continue

                await self._send(ws, {"type": "error", "error": f"unknown message type: {mtype}"})

        except websockets.ConnectionClosed:
            pass
        finally:
            # Cleanup registrations
            if peer:
                if peer.kind == "server":
                    # Remove server if still mapped
                    if self.servers_by_name.get(peer.name) is peer:
                        self.servers_by_name.pop(peer.name, None)
                elif peer.kind == "client":
                    self.clients_by_ws.pop(ws, None)

            # Close any tunnels involving this ws
            to_close = [tid for tid, t in self.tunnels.items() if t.client.ws == ws or t.server.ws == ws]
            for tid in to_close:
                await self._close_tunnel(tid, "peer_disconnected")


async def main() -> None:
    proxy_psk = os.environ.get("PROXY_PSK", "").strip()
    if not proxy_psk:
        raise RuntimeError("Set PROXY_PSK environment variable for proxy access control.")

    proxy = Proxy(proxy_psk=proxy_psk)
    host = "0.0.0.0"
    port = 8765
    print(f"[proxy] listening on ws://{host}:{port}")
    async with websockets.serve(proxy.handler, host, port, ping_interval=30, ping_timeout=30):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
