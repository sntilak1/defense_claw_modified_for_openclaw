# Deploying DefenseClaw in a Container on Amazon Linux EC2

This guide walks through deploying DefenseClaw as a Docker container on an
Amazon Linux 2023 EC2 instance to secure a running OpenClaw installation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  EC2 Instance (Amazon Linux 2023)                       │
│                                                         │
│  ┌──────────────────────────┐  ┌─────────────────────┐ │
│  │  DefenseClaw Container   │  │  OpenClaw (host or  │ │
│  │                          │  │  separate container)│ │
│  │  • sidecar  :18970       │◄─┤  :18789             │ │
│  │  • guardrail :4000       │  │                     │ │
│  └──────────────────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

DefenseClaw's guardrail proxy intercepts all LLM traffic from OpenClaw on
port `4000`. The sidecar REST API runs on port `18970` and connects back to
OpenClaw's gateway on port `18789`.

---

## Prerequisites

- EC2 instance: **Amazon Linux 2023**, `t3.medium` or larger (2 vCPU / 4 GB RAM minimum)
- Security group inbound rules:
  - `22` (SSH) — your IP only
  - `4000` (guardrail proxy) — from OpenClaw host if not co-located
  - `18970` (sidecar API) — from OpenClaw host if not co-located
- OpenClaw already running and accessible from the EC2 instance

---

## Step 1 — Launch and Connect to EC2

Launch an Amazon Linux 2023 instance from the AWS Console or CLI, then SSH in:

```bash
ssh -i your-key.pem ec2-user@<EC2_PUBLIC_IP>
```

---

## Step 2 — Install Docker

```bash
sudo dnf update -y
sudo dnf install -y docker git
sudo systemctl enable --now docker
sudo usermod -aG docker ec2-user
```

Log out and back in for the group change to take effect, then verify:

```bash
docker --version
```

---

## Step 3 — Clone the Repository

```bash
git clone https://github.com/sntilak1/defense_claw_modified_for_openclaw.git
cd defense_claw_modified_for_openclaw
```

---

## Step 4 — Configure Environment

Create a `.env` file with your runtime settings. DefenseClaw mounts this into
the container at startup:

```bash
cat > .env <<EOF
# Required: OpenClaw gateway auth token
# Find this in ~/.openclaw/openclaw.json → gateway.auth.token on the OpenClaw host
OPENCLAW_GATEWAY_TOKEN=your_openclaw_token_here

# Optional: LLM API key for the AI-based guardrail judge and scanners
# Without this, rule-based (regex/YARA) detection still works
# DEFENSECLAW_LLM_KEY=sk-ant-...

# Guardrail mode: observe (log only) or action (block threats)
GUARDRAIL_MODE=observe
EOF
```

> **Finding your OpenClaw gateway token:** On the machine running OpenClaw,
> run `cat ~/.openclaw/openclaw.json | grep token` or check the OpenClaw
> dashboard. The token is also auto-detected by `defenseclaw quickstart`.

---

## Step 5 — Build the Docker Image

```bash
docker build -t defenseclaw:latest .
```

This runs a multi-stage build:
1. Compiles the Go gateway binary
2. Installs the Python CLI and all scanner dependencies into a venv
3. Builds the TypeScript OpenClaw plugin
4. Produces a minimal Debian-slim runtime image (~500 MB)

Build time is approximately 5–10 minutes on a `t3.medium` (mostly Python
dependency downloads). Subsequent builds are faster due to Docker layer caching.

---

## Step 6 — Run the Container

### Option A — OpenClaw running on the same EC2 host

Use `--add-host=host-gateway:host-gateway` so the container can reach services
on the EC2 host network:

```bash
docker run -d \
  --name defenseclaw \
  --restart unless-stopped \
  --add-host=host-gateway:host-gateway \
  -p 4000:4000 \
  -p 18970:18970 \
  -v defenseclaw-data:/root/.defenseclaw \
  --env-file .env \
  -e OPENCLAW_HOST=host-gateway \
  -e OPENCLAW_PORT=18789 \
  defenseclaw:latest
```

### Option B — OpenClaw running on a separate host or container

Replace `OPENCLAW_HOST` with the IP or hostname of your OpenClaw machine:

```bash
docker run -d \
  --name defenseclaw \
  --restart unless-stopped \
  -p 4000:4000 \
  -p 18970:18970 \
  -v defenseclaw-data:/root/.defenseclaw \
  --env-file .env \
  -e OPENCLAW_HOST=<OPENCLAW_IP_OR_HOSTNAME> \
  -e OPENCLAW_PORT=18789 \
  defenseclaw:latest
```

### Option C — Docker Compose (recommended for production)

Create a `docker-compose.prod.yml`:

```yaml
services:
  defenseclaw:
    image: defenseclaw:latest
    build: .
    restart: unless-stopped
    ports:
      - "4000:4000"
      - "18970:18970"
    volumes:
      - defenseclaw-data:/root/.defenseclaw
    env_file: .env
    environment:
      - OPENCLAW_HOST=${OPENCLAW_HOST:-host-gateway}
      - OPENCLAW_PORT=${OPENCLAW_PORT:-18789}
      - GUARDRAIL_MODE=${GUARDRAIL_MODE:-observe}
    extra_hosts:
      - "host-gateway:host-gateway"
    healthcheck:
      test: ["CMD", "defenseclaw", "doctor"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s

volumes:
  defenseclaw-data:
```

Run with:

```bash
docker compose -f docker-compose.prod.yml up -d
```

---

## Step 7 — Verify the Deployment

Check that the container started cleanly:

```bash
docker logs defenseclaw
```

You should see:
```
[entrypoint] First run — initializing DefenseClaw...
[entrypoint] Starting defenseclaw-gateway...
```

Run a health check inside the container:

```bash
docker exec defenseclaw defenseclaw doctor
```

Expected output:
```
[PASS] Config file
[PASS] Audit database
[PASS] Sidecar API        — running
[PASS] OpenClaw gateway   — 127.0.0.1:18789
[PASS] Guardrail proxy    — healthy on port 4000
```

---

## Step 8 — Point OpenClaw at the Guardrail Proxy

For DefenseClaw to inspect LLM traffic, OpenClaw must route its API calls
through the guardrail proxy at `http://<EC2_IP>:4000`.

On the OpenClaw host, update `~/.openclaw/openclaw.json` to set the LLM
provider base URL to the DefenseClaw guardrail proxy:

```json
{
  "agents": {
    "defaults": {
      "model": {
        "provider": "anthropic",
        "baseUrl": "http://<EC2_IP>:4000"
      }
    }
  }
}
```

Then restart OpenClaw. All LLM calls will now flow through DefenseClaw's
guardrail for inspection and audit logging.

> If OpenClaw is on the same EC2 host, use `http://127.0.0.1:4000` as the
> base URL instead.

---

## Viewing Audit Logs

Query the audit log from inside the container:

```bash
docker exec defenseclaw defenseclaw audit query
```

Or stream the sidecar logs in real time:

```bash
docker logs -f defenseclaw
```

---

## Switching to Action Mode (Blocking)

Once you're satisfied with what `observe` mode is logging, switch to `action`
mode to actively block detected threats:

```bash
docker exec defenseclaw defenseclaw setup guardrail --mode action --non-interactive
```

Restart the container to apply:

```bash
docker restart defenseclaw
```

---

## Persisting Data Across Container Restarts

The `defenseclaw-data` Docker volume persists:

| Path | Contents |
|------|----------|
| `/root/.defenseclaw/config.yaml` | All configuration |
| `/root/.defenseclaw/audit.db` | Audit log and scan results |
| `/root/.defenseclaw/.env` | API keys |
| `/root/.defenseclaw/policies/` | Rule packs and Rego policies |

The volume survives `docker restart` and `docker stop`/`start`. It is **not**
deleted by `docker rm` unless you explicitly run `docker volume rm defenseclaw-data`.

---

## Updating DefenseClaw

To pull the latest code and rebuild:

```bash
git pull
docker build -t defenseclaw:latest .
docker stop defenseclaw && docker rm defenseclaw
# Re-run the docker run command from Step 6
```

Your `defenseclaw-data` volume is preserved across rebuilds.

---

## Troubleshooting

### Container exits immediately

Check the logs:
```bash
docker logs defenseclaw
```

Common causes:
- `OPENCLAW_GATEWAY_TOKEN` not set or wrong — verify the token from `openclaw.json`
- OpenClaw host unreachable — check `OPENCLAW_HOST` and security group rules

### Guardrail proxy unreachable from OpenClaw

Verify port `4000` is open in the EC2 security group inbound rules and that
the container is actually listening:
```bash
docker exec defenseclaw curl -s http://localhost:4000/health
```

### "sidecar not running" in doctor output

The gateway may not have started yet (it takes a few seconds on first init):
```bash
docker exec defenseclaw defenseclaw-gateway status
docker exec defenseclaw defenseclaw-gateway start
```

### Resetting to a clean state

To wipe the config and start fresh (preserves the image):
```bash
docker stop defenseclaw && docker rm defenseclaw
docker volume rm defenseclaw-data
# Re-run the docker run command from Step 6
```

---

## Security Notes

- The `.env` file contains your `OPENCLAW_GATEWAY_TOKEN`. Do not commit it to git (it is in `.gitignore`).
- Restrict the EC2 security group so ports `4000` and `18970` are only accessible from the OpenClaw host IP, not `0.0.0.0/0`.
- Run the container as a non-root user in production by adding `--user` to the `docker run` command and adjusting the volume mount permissions.
- Rotate the `OPENCLAW_GATEWAY_TOKEN` periodically and update the `.env` file and container environment.
