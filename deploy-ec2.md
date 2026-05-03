# DefenseClaw — EC2 Container Deployment

Steps to build and run DefenseClaw as a Docker container on this Amazon Linux EC2 host.

The repository is already cloned at `/home/ec2-user/defense_claw_modified_for_openclaw`.
Docker is already installed and running.

---

## 1. Move into the repo

```bash
cd /home/ec2-user/defense_claw_modified_for_openclaw
```

---

## 2. Build the image

The Dockerfile is a two-stage build: Go 1.26 + Python + Node compile everything in the
builder stage; the runtime stage is `debian:bookworm-slim`.

```bash
docker compose build
```

This takes a few minutes on the first run. It compiles:
- Go gateway binary (`defenseclaw-gateway`)
- Python CLI venv (via `uv`)
- TypeScript OpenClaw plugin (via `npm`)

> **If the build is killed with exit code 137** the instance is out of memory during
> `pnpm/npm install`. Upgrade to a t3.medium (2 vCPU / 4 GB) for the build.

---

## 3. Start the container

```bash
docker compose up -d
```

The entrypoint automatically runs `defenseclaw init` on first start, configures the
gateway connection, and sets guardrail mode to `observe`.

Watch the logs:

```bash
docker compose logs -f defenseclaw
```

Expected startup lines:

```
[entrypoint] First run — initializing DefenseClaw...
[entrypoint] Starting defenseclaw-gateway...
```

---

## 4. Verify it is running

Check the sidecar REST API from the host:

```bash
curl -s http://127.0.0.1:18970/status
```

Check the guardrail proxy:

```bash
curl -s http://127.0.0.1:4000/healthz
```

---

## 5. Point OpenClaw at DefenseClaw

Both ports are bound to `127.0.0.1` on the host.

| Port  | Purpose                                                     |
|-------|-------------------------------------------------------------|
| 4000  | Guardrail proxy — route OpenClaw LLM traffic through this   |
| 18970 | Sidecar REST API — CLI and plugin management calls          |

In your OpenClaw configuration set the proxy endpoint to `http://127.0.0.1:4000`.

If OpenClaw is running in its own container on the same host, add the EC2 host IP
(or use `host-gateway` which is pre-wired in `docker-compose.yml`):

```
http://host-gateway:4000
```

---

## 6. Configure the gateway connection (optional override)

The entrypoint reads these environment variables. Override them in `docker-compose.yml`
under `environment`, or export them before running `docker compose up`.

| Variable          | Default         | Description                            |
|-------------------|-----------------|----------------------------------------|
| `OPENCLAW_HOST`   | `host-gateway`  | Hostname where OpenClaw gateway runs   |
| `OPENCLAW_PORT`   | `18789`         | OpenClaw gateway port                  |
| `GUARDRAIL_MODE`  | `observe`       | `observe` (log only) or `enforce`      |
| `DEFENSECLAW_DATA_DIR` | `/data`    | Config + audit DB path inside container |

---

## 7. Persist data

All state (config, audit database, scanners cache) lives in the Docker named volume
`defenseclaw_defenseclaw-data`. It survives container restarts and image rebuilds.

```bash
# Inspect the volume
docker volume inspect defenseclaw_defenseclaw-data

# Never use -v when stopping unless you want to wipe state
docker compose down        # safe — keeps the volume
docker compose down -v     # DESTRUCTIVE — deletes the volume
```

---

## 8. Auto-start on reboot

The `restart: unless-stopped` policy in `docker-compose.yml` restarts the container
when Docker starts. Docker starts automatically via systemd on Amazon Linux.

Confirm:

```bash
sudo systemctl is-enabled docker
# enabled
```

---

## 9. Updates

```bash
cd /home/ec2-user/defense_claw_modified_for_openclaw
git pull
docker compose build
docker compose up -d
```

State in the named volume is preserved across rebuilds.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Build killed, `exit code 137` | OOM during npm/uv install | Upgrade instance to t3.medium+ |
| `curl: (7) Failed to connect to 127.0.0.1 port 18970` | Container not running | `docker compose ps` then `docker compose logs defenseclaw` |
| `[entrypoint] First run` repeats every restart | Volume not mounted | Check `docker volume ls` for `defenseclaw_defenseclaw-data` |
| Gateway exits immediately after init | Missing config or bad env var | `docker compose logs defenseclaw` for the full error |
| Port 4000 or 18970 already in use | Another process on the host | `sudo ss -tlnp | grep -E '4000|18970'` to find it |
