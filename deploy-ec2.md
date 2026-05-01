# OpenClaw Gateway — EC2 Deployment Guide (Private Subnet / SSM)

One-time steps to clone, build, and run OpenClaw Gateway as a Docker container on a private-subnet EC2 instance accessed exclusively via AWS Systems Manager (SSM).

---

## Prerequisites

### AWS-side requirements

| Requirement     | Detail                                                                                                                                                                 |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **NAT gateway** | The private subnet must route `0.0.0.0/0` through a NAT gateway. Needed for `git clone`, Docker base image pulls, and the Bun installer during `docker compose build`. |
| **SSM Agent**   | Pre-installed and running on Ubuntu 20.04+ official AWS AMIs. Already confirmed working.                                                                               |

### EC2 instance

| Property      | Recommendation                                                                                                           |
| ------------- | ------------------------------------------------------------------------------------------------------------------------ |
| AMI           | Ubuntu 24.04 LTS (64-bit x86) — use the official AWS Marketplace AMI                                                     |
| Instance type | **t3.medium** minimum for the Docker build (2 vCPU / 4 GB RAM). Downsize to t3.small after first build if memory allows. |
| Storage       | 20 GB gp3 root volume                                                                                                    |
| Key pair      | None required — access is via SSM only                                                                                   |
| Subnet        | Private (no public IP needed)                                                                                            |

> **OOM warning:** `docker compose build` runs `pnpm install` + a full TypeScript compile. On t3.small (2 GB RAM) this will be killed with `exit code 137`. Build on t3.medium or larger, then resize if needed.

### Security group

No inbound rules are required. SSM communicates outbound over HTTPS (port 443) through the NAT gateway — it does not need port 22 or any open inbound port.

| Direction | Port | Purpose                                   |
| --------- | ---- | ----------------------------------------- |
| Outbound  | 443  | SSM, Docker Hub, GitHub (via NAT gateway) |

### Laptop requirements

Install both before starting:

```bash
# AWS CLI v2
# https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

# Session Manager plugin for AWS CLI
# https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html
```

Confirm:

```bash
aws --version
session-manager-plugin --version
```

---

## 1. Open an SSM session on the instance

Find your instance ID in the EC2 console, then:

```bash
aws ssm start-session --target i-0123456789abcdef0
```

This drops you into a shell on the instance. All remaining steps run **inside this session** unless noted.

The default SSM shell user is `ssm-user`. Switch to `ubuntu` for consistent home-directory paths:

```bash
sudo -i -u ubuntu
```

---

## 2. Install Docker

```bash
sudo apt-get update
sudo apt-get install -y git curl ca-certificates

# Install Docker Engine via the official convenience script
curl -fsSL https://get.docker.com | sudo sh

# Allow the ubuntu user to run Docker without sudo
sudo usermod -aG docker ubuntu

# Apply group membership without re-logging in
newgrp docker
```

Verify:

```bash
docker --version
docker compose version
```

---

## 3. Clone the repository

```bash
git clone https://github.com/openclaw/openclaw.git
cd openclaw
```

---

## 4. Create persistent host directories

Docker containers are ephemeral. State must live on the host so it survives restarts and image rebuilds.

```bash
mkdir -p /home/ubuntu/.openclaw/workspace

# Set ownership to the container user (uid 1000 = node inside the image)
sudo chown -R 1000:1000 /home/ubuntu/.openclaw
```

---

## 5. Configure environment variables

Create a `.env` file in the repository root. **Do not commit this file.**

```bash
cat > /home/ubuntu/openclaw/.env <<'EOF'
OPENCLAW_IMAGE=openclaw:local
OPENCLAW_GATEWAY_TOKEN=
OPENCLAW_GATEWAY_BIND=lan
OPENCLAW_GATEWAY_PORT=18789

OPENCLAW_CONFIG_DIR=/home/ubuntu/.openclaw
OPENCLAW_WORKSPACE_DIR=/home/ubuntu/.openclaw/workspace

# Required only if you use the Gmail skill; generate with: openssl rand -hex 32
GOG_KEYRING_PASSWORD=

XDG_CONFIG_HOME=/home/node/.openclaw
TZ=UTC
EOF
```

- Leave `OPENCLAW_GATEWAY_TOKEN` blank on first run — OpenClaw writes a random token to config automatically.
- Fill in `GOG_KEYRING_PASSWORD` only if you use Gmail integration.

---

## 6. Bind the gateway port to loopback

The gateway port must be bound to `127.0.0.1` on the EC2 instance. SSM port forwarding will tunnel it to your laptop — it must not be exposed on the network interface.

Edit `docker-compose.yml` and change the `ports` block for `openclaw-gateway`:

```yaml
ports:
  - "127.0.0.1:${OPENCLAW_GATEWAY_PORT:-18789}:18789"
  - "127.0.0.1:${OPENCLAW_BRIDGE_PORT:-18790}:18790"
```

---

## 7. Build and start

```bash
cd /home/ubuntu/openclaw
docker compose build
docker compose up -d openclaw-gateway
```

Monitor startup:

```bash
docker compose logs -f openclaw-gateway
```

Expected output:

```
[gateway] listening on ws://0.0.0.0:18789
```

Check the health endpoint from inside the instance:

```bash
curl -s http://127.0.0.1:18789/healthz
```

---

## 8. Access the web UI via SSM port forwarding

Run this on **your laptop** — not inside the SSM session:

```bash
aws ssm start-session \
  --target i-0123456789abcdef0 \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["18789"],"localPortNumber":["18789"]}'
```

Then open `http://127.0.0.1:18789/` in your browser.

### Find the gateway token

Inside the SSM session on the instance:

```bash
grep -i token /home/ubuntu/.openclaw/openclaw.json
```

Paste that token into the browser prompt.

### Keep the port-forward running

The port-forward session must stay open while you use the UI. Run it in a dedicated terminal tab on your laptop. It will reconnect automatically if the SSM session is interrupted.

---

## 9. What persists where

| Component                        | Location                                           | Persistence                                                              |
| -------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------ |
| Gateway config (`openclaw.json`) | `/home/ubuntu/.openclaw/`                          | Host bind mount — survives restarts and rebuilds                         |
| Auth profiles (OAuth, API keys)  | `/home/ubuntu/.openclaw/agents/`                   | Host bind mount                                                          |
| Agent workspace                  | `/home/ubuntu/.openclaw/workspace/`                | Host bind mount                                                          |
| Plugin runtime deps              | Docker named volume `openclaw-plugin-runtime-deps` | Docker volume — survives restarts; recreated on `docker compose down -v` |
| External binaries                | `/usr/local/bin/` inside image                     | Baked at build time — must rebuild image to update                       |
| Container filesystem             | Ephemeral                                          | Safe to destroy                                                          |

---

## 10. Auto-start on reboot

The `restart: unless-stopped` policy in `docker-compose.yml` restarts the container automatically when Docker starts. Docker itself starts via systemd on boot.

Verify Docker is enabled:

```bash
sudo systemctl is-enabled docker
# Should output: enabled
```

If not:

```bash
sudo systemctl enable docker
```

---

## 11. Updates

Inside the SSM session:

```bash
cd /home/ubuntu/openclaw
git pull
docker compose build
docker compose up -d
```

Config and workspace are on the host — no state is lost during rebuilds.

---

## Troubleshooting

| Symptom                                       | Cause                                                         | Fix                                                                                           |
| --------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Build killed / `exit code 137`                | OOM during `pnpm install`                                     | Upgrade to t3.medium or larger                                                                |
| Port forward connects but browser times out   | Port not bound to `127.0.0.1` on host, or gateway not running | Check `docker compose logs openclaw-gateway`; verify loopback binding in `docker-compose.yml` |
| Gateway exits immediately                     | Missing config or bad `.env`                                  | `docker compose logs openclaw-gateway`                                                        |
| State lost after restart                      | Used `docker compose down -v`                                 | The `-v` flag removes named volumes — use `docker compose down` without it                    |
| Permission denied on `/home/ubuntu/.openclaw` | Wrong ownership (must be uid 1000)                            | `sudo chown -R 1000:1000 /home/ubuntu/.openclaw`                                              |
