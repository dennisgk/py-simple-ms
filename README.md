# py-simple-ms

A minimal Python client/proxy/server protocol for remote Python environment and file/session operations.

## Clone

```bash
git clone https://github.com/dennisgk/py-simple-ms.git
cd py-simple-ms
```

## Components

- `py-simple-ms-proxy/proxy.py`: WebSocket relay that routes messages between client and server by tunnel ID.
- `py-simple-ms-server/server.py`: Remote server endpoint. Authenticates client, decrypts commands, runs pyenv/session/file operations.
- `py-simple-ms-client/py_simple_ms_client/client.py`: Client SDK + demo usage.
- `py-simple-ms-server/session_worker.py`: Worker process used by server sessions for repeated `exec` calls.

## Transport And Security

- Transport: WebSocket frames between all components.
- Frame encoding: every outbound message is JSON encoded then Brotli compressed.
- Proxy access gate: `PROXY_PSK` is validated by proxy during server/client registration.
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

Progress is printed on the client command line for `file_put`, `file_get`, and `mount_tree`.

## Experimental WebRTC Transfer Mode

- `file_put`, `file_get`, and `mount_tree` support `transfer_mode="webrtc"`.
- If WebRTC setup fails, client falls back automatically to websocket transfer.
- Server requires `aiortc` installed (included in `py-simple-ms-server/requirements.txt`).
- Proxy now advertises ICE server info to both client and server during registration/tunnel open.
- If no proxy ICE info is available, both sides default to `stun:stun.l.google.com:19302`.
- Optional overrides still supported with `WEBRTC_ICE_SERVERS_JSON` (or client CLI arg).

Examples:

```python
await c.file_put("/remote/data.bin", "local/data.bin", transfer_mode="webrtc")
await c.file_get("/remote/data.bin", "local/data.bin", transfer_mode="webrtc")
await c.mount_tree("/remote/workflow", "./workflow", transfer_mode="webrtc", chunk_size=2*1024*1024)
```

Optional ICE config example (same JSON on both sides):

```bash
export WEBRTC_ICE_SERVERS_JSON='[{"urls":["stun:stun.l.google.com:19302"]},{"urls":["turn:turn.example.com:3478"],"username":"user","credential":"pass"}]'
```

Client CLI can override with:

```bash
--webrtc-ice-servers-json '[{"urls":["stun:stun.l.google.com:19302"]}]'
```

When using `py-simple-ms-proxy/docker-compose.yml`, TURN is started automatically and proxy advertises both STUN and TURN to clients/servers.

## Session Exec Streaming

- `session_exec` streams runtime output while code is still executing.
- The worker emits line-delimited events for `stdout` and `stderr`.
- Server forwards these events as encrypted `session_stream` messages before the final `exec_result`.

## Setup

You can fetch only the `py-simple-ms-server` folder using sparse checkout:

```bash
git clone --filter=blob:none --no-checkout https://github.com/dennisgk/py-simple-ms.git
cd py-simple-ms
git sparse-checkout init --cone
git sparse-checkout set py-simple-ms-server
git checkout main
```

Then install server dependencies:

```bash
pip install -r py-simple-ms-server/requirements.txt
```

### Client Install (Linux + pyenv)

```bash
# select/activate your pyenv environment first
pyenv activate <env-name>

pip install git+https://github.com/dennisgk/py-simple-ms.git#subdirectory=py-simple-ms-client
```

### Client Install (Windows + venv)

```powershell
# activate your venv first
.\.venv\Scripts\Activate.ps1

pip install git+https://github.com/dennisgk/py-simple-ms.git#subdirectory=py-simple-ms-client
```

Client dependencies are installed automatically from `py-simple-ms-client/pyproject.toml`.

Verify install/import:

```bash
python -c "from py_simple_ms_client import RemoteServerClient; print(RemoteServerClient.__name__)"
```

## Run

Use the same `PSK_HEX` for client and server.
Use the same `PROXY_PSK` for proxy, server, and client.

```bash
# Example 32-byte key (64 hex chars)
export PSK_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
export PROXY_PSK=replace-with-shared-proxy-key
```

Start proxy (keeps env-style config):

```bash
python3 py-simple-ms-proxy/proxy.py
```

Start server (keeps env-style config):

```bash
export PROXY_URL=ws://127.0.0.1:8765
export SERVER_NAME=server-1
export PROXY_PSK="$PROXY_PSK"
python3 py-simple-ms-server/server.py
```

Server can also load these from `py-simple-ms-server/.env`:

```dotenv
PROXY_URL=ws://127.0.0.1:8765
SERVER_NAME=server-1
PROXY_PSK=replace-with-shared-proxy-key
PSK_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Start client demo (pass required args directly):

```bash
py-simple-ms-client \
  --proxy-url ws://127.0.0.1:8765 \
  --server-name server-1 \
  --psk-hex "$PSK_HEX" \
  --proxy-psk "$PROXY_PSK"
```

## Docker (Proxy Sample)

Sample Dockerfile is at `py-simple-ms-proxy/Dockerfile` and clones this repo during build.
Compose file is at `py-simple-ms-proxy/docker-compose.yml`.

```bash
docker build -f py-simple-ms-proxy/Dockerfile -t py-simple-ms-proxy:sample .
docker run --rm -p 8765:8765 py-simple-ms-proxy:sample
```

Or with Docker Compose:

```bash
docker compose -f py-simple-ms-proxy/docker-compose.yml up --build -d
docker compose -f py-simple-ms-proxy/docker-compose.yml logs -f proxy
docker compose -f py-simple-ms-proxy/docker-compose.yml down
```

Set `PROXY_PSK` in your shell (or `.env` for compose) before `docker compose up`.

For TURN reachability from client/server hosts, set:

```bash
export TURN_PUBLIC_HOST=<host-or-ip-reachable-by-both-sides>
export TURN_EXTERNAL_IP=<public-ip-of-turn-host>
export TURN_USER=pyms
export TURN_PASSWORD=pyms-pass
```

## Notes

- Server-side pyenv commands require `pyenv` (and for env listing, `pyenv-virtualenv`).
- Session execution runs code inside the selected `PYENV_VERSION` via `pyenv exec python`.
- File deletion is no longer a protocol command; perform deletes via Python code executed in a session.
