# aporto

Self-hosted developer tunnels inspired by ngrok, composed of a Go reverse proxy/control plane (`aporto-server`) and a cross-platform CLI (`aporto`).

## Architecture Recap

- **Server binary** (deploys to your VPS)
  - Control plane API on a private interface (`/v1/tunnels`) for issuing tunnel credentials.
  - Public HTTP(S) reverse proxy that routes `https://{subdomain}.{domain}` to the correct tunnel session.
  - SQLite metadata store for tunnel definitions and heartbeat timestamps.
- **CLI binary** (runs on developer machines)
  - Stores tunnel credentials locally (`~/.config/aporto/config.yaml`).
  - Opens a persistent WebSocket back to the control plane and proxies HTTP requests to a local service.
  - Handles retries, heartbeats, and structured logs.



## CLI Usage

1. **Build/install**
   ```bash
   cd cli && go install ./cmd/aporto
   ```
2. **Generate a keypair (first run only)**
   ```bash
   aporto init
   ```
   - Copy the printed public key into the server’s `authorized_keys` file.
3. **Login**
   ```bash
   aporto login --api-url https://control.example.com
   ```
   - Stores the control-plane URL and verifies that your key is authorized. No tunnel is created yet.
4. **Start tunneling / request a tunnel**
   ```bash
   aporto 3000 --name demo
   ```
   - First run: the CLI asks the server for a tunnel using the provided name (optional) as the subdomain and saves the assigned ID + secret. Subsequent runs reuse the stored tunnel unless you pass `--name` again to request a different hostname. Names can be reclaimed while nobody is actively connected; if a tunnel is live under that name, the server will reject the change.
   - Omit `--name` to get a fresh random subdomain every time (e.g. `https://gpdn6w8kzq.example.com`).
   - You can still run `aporto tunnel start` explicitly, or override the target per run via `aporto tunnel start --local-addr http://127.0.0.1:8080`.
5. **Inspect config**
   ```bash
   aporto status
   ```

When the CLI is running, any request to `https://subdomain.example.com` is reverse-proxied to the local address.

## VPS Deployment (Docker + Caddy)
1. **Set DNS**
   - Point `control.example.com` (or similar) and `*.apps.example.com` to the host running Docker.
2. **Configure server + env**
   - Edit `deploy/server-config.docker.yaml`, set `domain` to your tunnel base (e.g. `apps.example.com`) and generate a strong `admin_token`.
   - Populate `deploy/authorized_keys` with the base64 public keys of developers who should be able to self-provision tunnels (one per line).
   - Create a `.env` file alongside `docker-compose.yml` (the compose file already defaults `APORTO_ON_DEMAND_CHECK` to the server's internal allow-list endpoint; override it only if you host your own validation service):
     ```dotenv
     ACME_EMAIL=ops@example.com
     APORTO_CONTROL_DOMAIN=control.example.com
     APORTO_TUNNEL_DOMAIN=apps.example.com
     # Optional override:
     # APORTO_ON_DEMAND_CHECK=https://your-allowlist-endpoint
     ```
3. **Launch**
   ```bash
   docker compose up -d --build
   ```
   - Caddy listens on `80/443`, handles HTTPS for both the control domain and any `*.apps.example.com` host, and proxies to the `aporto-server` container on ports `9090` (control plane) and `8080` (tunnels).
   - Certificates are issued on-demand per subdomain and validated via `/v1/tls/allow` on the server; if you need different rules, adjust `APORTO_ON_DEMAND_CHECK` to point at your own allow-list endpoint.
4. **Manage data**
   - SQLite DB and tunnel state live in the `server_data` volume; Caddy stores ACME certs in `caddy_data`.

