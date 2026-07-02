# Sentinel Cloud Mock

Local website and API mock for Sentinel Anticheat.

## Run

```bash
npm run dev
```

The API listens on `http://127.0.0.1:8787` by default.

Open the public site at:

```text
http://127.0.0.1:8787/
```

Open the admin login at:

```text
http://127.0.0.1:8787/admin
```

## Environment

Copy `.env.example` values into your deployment environment or export them manually.

```bash
export SENTINEL_SHARED_SECRET=CHANGE_ME_SENTINEL_SHARED_SECRET
export SENTINEL_LICENSE_KEYS=CHANGE_ME_SENTINEL_LICENSE
export SENTINEL_SERVER_KEYS=CHANGE_ME_SENTINEL_SERVER_KEY
export SENTINEL_ADMIN_USER=admin
export SENTINEL_ADMIN_PASSWORD=CHANGE_ME_ADMIN_PASSWORD
npm run dev
```

## Endpoints

- `GET /health`
- `GET /`
- `GET /download`
- `GET /admin`
- `GET /admin/reports?token=CHANGE_ME_DASHBOARD_TOKEN`
- `GET /admin/bans?token=CHANGE_ME_DASHBOARD_TOKEN`
- `GET /admin/report/<id>.pdf?token=CHANGE_ME_DASHBOARD_TOKEN`
- `GET /auth/discord/start?state=<state>`
- `POST /v1/license/verify`
- `POST /v1/agent/discord/status`
- `POST /v1/agent/connect`
- `POST /v1/agent/heartbeat`
- `POST /v1/agent/report`
- `POST /v1/agent/alert`
- `POST /v1/server/session/check`
- `POST /v1/detection/report`
- `POST /v1/events/list`

This mock stores reports, sessions, and bans in memory only. Production should use a real database, official Discord OAuth2, per-customer keys, rate limits, audit logs, and asymmetric response signing.

