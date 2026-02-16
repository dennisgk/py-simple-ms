# py-simple-ms

A minimal Python client/proxy/server protocol for remote Python environment and file/session operations.

## Components

- `py-simple-ms-proxy/proxy.py`: WebSocket relay that routes messages between client and server by tunnel ID.
- `py-simple-ms-server/server.py`: Remote server endpoint. Authenticates client, decrypts commands, runs pyenv/session/file operations.
- `py-simple-ms-client/client.py`: Client SDK + demo usage.
- `py-simple-ms-server/session_worker.py`: Worker process used by server sessions for repeated `exec` calls.

## Transport And Security

- Transport: WebSocket frames between all components.
- Frame encoding: every outbound message is JSON encoded then Brotli compressed.
- Tunnel crypto: after auth, payloads use ChaCha20-Poly1305 with per-message sequence numbers.
- Auth: pre-shared key (`PSK_HEX`) challenge-response with HMAC-SHA256.
- Key derivation: HKDF-SHA256 derives directional keys (`c2s`, `s2c`).

## Protocol Flow

1. Server connects to proxy and sends `register_server`.
2. Client connects to proxy and sends `register_client`.
3. Client requests `client_connect` to a server name.
4. Proxy opens a `tunnel_id` and notifies both sides with `tunnel_open`.
5. Client/server run auth handshake (`auth_hello` -> `auth_challenge` -> `auth_proof` -> `auth_ok`).
6. Client sends encrypted request messages with `req_id`; server replies with matching `req_id`.

## Chunked File Transfer

Large file transfer is split into chunks to avoid oversized encrypted payloads.

Upload (client -> server):
- `file_put_begin(path)` -> `upload_id`
- repeated `file_put_chunk(upload_id, seq, data_b64)`
- `file_put_end(upload_id)`
- optional `file_put_abort(upload_id)` on failure

Download (server -> client):
- `file_get_begin(path)` -> `download_id`
- repeated `file_get_chunk(download_id, chunk_size)` until `done=true`
- `file_get_end(download_id)`

## Session Exec Streaming

- `session_exec` now streams runtime output while code is still executing.
- The worker emits line-delimited events for `stdout` and `stderr`.
- Server forwards these events as encrypted `session_stream` messages before the final `exec_result`.

## Setup

Install dependencies per component.

```powershell
pip install -r py-simple-ms-proxy/requirements.txt
pip install -r py-simple-ms-server/requirements.txt
pip install -r py-simple-ms-client/requirements.txt
```

## Run

Use the same `PSK_HEX` for client and server.

```powershell
# Example 32-byte key (64 hex chars)
$env:PSK_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
```

Start proxy:

```powershell
python py-simple-ms-proxy/proxy.py
```

Start server:

```powershell
$env:PROXY_URL = "ws://127.0.0.1:8765"
$env:SERVER_NAME = "server-1"
python py-simple-ms-server/server.py
```

Start client demo:

```powershell
$env:PROXY_URL = "ws://127.0.0.1:8765"
$env:SERVER_NAME = "server-1"
python py-simple-ms-client/client.py
```

## Notes

- Server-side pyenv commands require `pyenv` (and for env listing, `pyenv-virtualenv`).
- Session execution runs code inside the selected `PYENV_VERSION` via `pyenv exec python`.
