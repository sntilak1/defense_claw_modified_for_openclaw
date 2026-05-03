# DefenseClaw ↔ OpenClaw Docker Pairing Guide

This guide documents how to get the DefenseClaw sidecar container connected to
a containerised OpenClaw gateway, covering the three root-cause fixes and the
manual bootstrap steps required the first time (or after a full teardown).

---

## Background

When DefenseClaw and OpenClaw both run in Docker (rather than on the same bare
host), several assumptions in the default configuration break:

| Assumption | Problem in Docker |
|---|---|
| `host-gateway` uses TLS | OpenClaw serves plain `ws://`; DefenseClaw dials `wss://` |
| `~/.openclaw` is shared | Each container has its own filesystem; `paired.json` is not shared |
| Device token is pre-issued | The gateway requires an active token entry before it will accept a connect |

---

## Permanent fixes (already applied to this repo)

### 1. Plain WebSocket — `DEFENSECLAW_NO_TLS=1`

**File:** `internal/gateway/sidecar.go`

Added an env-var override so operators can force `ws://` without changing
`gateway.tls` in config:

```go
switch strings.ToLower(strings.TrimSpace(os.Getenv("DEFENSECLAW_NO_TLS"))) {
case "1", "true", "yes", "on":
    cfg.Gateway.NoTLS = true
default:
    if !cfg.Gateway.RequiresTLSWithMode(&cfg.OpenShell) {
        cfg.Gateway.NoTLS = true
    }
}
```

**File:** `docker-compose.yml`

```yaml
environment:
  DEFENSECLAW_NO_TLS: "1"
```

### 2. Shared OpenClaw config volume

**File:** `docker-compose.yml`

Mount the host-side OpenClaw config directory into the DefenseClaw container so
`RepairPairing` writes to the real `paired.json`:

```yaml
volumes:
  - defenseclaw-data:/root/.defenseclaw
  - /opt/openclaw/config:/root/.openclaw   # shared with OpenClaw containers
```

### 3. Gateway auth token

**File:** `docker-compose.yml`

Pass OpenClaw's shared gateway auth token via env var so the connect handshake
can authenticate:

```yaml
environment:
  OPENCLAW_GATEWAY_TOKEN: ${OPENCLAW_GATEWAY_TOKEN:-}
```

Start the stack with the token exported:

```bash
export OPENCLAW_GATEWAY_TOKEN=$(python3 -c "
import json
d = json.load(open('/opt/openclaw/config/openclaw.json'))
print(d['gateway']['auth']['token'])
")
docker compose up -d
```

---

## First-time bootstrap (manual, one-off)

OpenClaw requires device pairing approval before it will accept connects.
The first time (or after wiping the OpenClaw config), follow these steps.

### Step 1 — Start the stack

```bash
export OPENCLAW_GATEWAY_TOKEN=$(python3 -c "
import json
d = json.load(open('/opt/openclaw/config/openclaw.json'))
print(d['gateway']['auth']['token'])
")
docker compose up -d
```

DefenseClaw will connect, fail with `NOT_PAIRED`, and automatically write its
device entry to `/opt/openclaw/config/devices/paired.json` via `RepairPairing`.

### Step 2 — Get the device ID and public key

```bash
python3 -c "
import json
d = json.load(open('/opt/openclaw/config/devices/paired.json'))
for k, v in d.items():
    if v.get('displayName') == 'defenseclaw-sidecar':
        print('deviceId:', k)
        print('publicKey:', v.get('publicKey'))
"
```

### Step 3 — Bootstrap the device token in `paired.json`

OpenClaw will not accept a connect from a device whose `tokens` object is
empty — `listEffectivePairedDeviceRoles` returns `[]` and triggers a
`role-upgrade` approval loop.  Bootstrap it with a random token:

```bash
python3 - << 'EOF'
import json, time, base64, os

DEVICE_ID = "<paste deviceId from Step 2>"

now_ms = int(time.time() * 1000)
token = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
scopes = ['operator.read', 'operator.write', 'operator.admin', 'operator.approvals']

paired_path = '/opt/openclaw/config/devices/paired.json'
with open(paired_path) as f:
    paired = json.load(f)

dev = paired[DEVICE_ID]
dev['scopes']         = scopes
dev['approvedScopes'] = scopes
dev['tokens'] = {
    'operator': {
        'token':        token,
        'role':         'operator',
        'scopes':       scopes,
        'createdAtMs':  now_ms,
        'lastUsedAtMs': now_ms,
    }
}
with open(paired_path, 'w') as f:
    json.dump(paired, f, indent=2)

# Clear any pending role-upgrade requests
with open('/opt/openclaw/config/devices/pending.json', 'w') as f:
    json.dump({}, f, indent=2)

print('Done. Token:', token)
EOF
```

### Step 4 — Restart the OpenClaw gateway

The gateway caches device state in memory.  Restart it once to pick up the
updated `paired.json`:

```bash
docker restart runtime_agent-openclaw-gateway-1
```

### Step 5 — Verify

```bash
docker exec defenseclaw defenseclaw-gateway status
```

Expected output:

```
Gateway:   RUNNING (since ...)
           protocol: 3
```

---

## What happens on subsequent restarts

| Event | Behaviour |
|---|---|
| DefenseClaw container restarts | Auto-repair re-writes its device entry to `paired.json`; no manual action needed |
| OpenClaw gateway restarts | Loads `paired.json` from disk (token is still there); DefenseClaw reconnects automatically within ~15 s |
| Full stack teardown (`docker compose down -v`) | Clears `defenseclaw-data` volume; device key is regenerated on next start — repeat bootstrap from Step 1 |
| OpenClaw config wiped | `paired.json` is cleared; repeat bootstrap from Step 1 |

> **Note:** If the OpenClaw gateway restarts and DefenseClaw's `RepairPairing`
> runs before the gateway finishes loading, the connect may fail once with
> `NOT_PAIRED` before succeeding on the next retry (~15 s).  This is normal.

---

## Troubleshooting

### `cannot execute: required file not found`

Python venv shebangs point to the builder-stage path.  Rebuild the image:

```bash
docker compose build
```

The Dockerfile now fixes shebangs and copies uv's managed Python into the
runtime stage.

### `wss://` TLS handshake error

`DEFENSECLAW_NO_TLS` is not set, or the image was built before the fix.
Ensure `docker-compose.yml` has `DEFENSECLAW_NO_TLS: "1"` and rebuild.

### `gateway token missing`

`OPENCLAW_GATEWAY_TOKEN` is not set.  Export it and recreate the container:

```bash
export OPENCLAW_GATEWAY_TOKEN=$(python3 -c "
import json
d = json.load(open('/opt/openclaw/config/openclaw.json'))
print(d['gateway']['auth']['token'])
")
docker compose up -d
```

### `role-upgrade` approval loop

The defenseclaw device entry in `paired.json` has `tokens: {}`.  Run
Step 3 and Step 4 above.

### Gateway keeps reconnecting after OpenClaw restart

Check the gateway log:

```bash
docker exec defenseclaw cat /root/.defenseclaw/gateway.log | tail -20
```

If `NOT_PAIRED` appears, the OpenClaw gateway cleared its state.  Rerun
Steps 3–4.

If `role-upgrade` appears, rerun Steps 3–4.
