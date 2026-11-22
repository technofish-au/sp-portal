# sp-portal

serverperch.com — the customer portal + licensing backend for the
ServerPerch on-prem monitoring appliance. Go service (chi + MariaDB +
embedded goose migrations + a SKIP LOCKED job queue) with a React/Mantine
web UI.

## Layout

- `cmd/sp-portal` — single binary: `serve`, `worker`, `migrate`,
  `admin create`, `healthcheck`, `version`
- `internal/<domain>` — one package per domain; each exposes `routes.go`
  mounted with a single `r.Mount` line in `internal/httpapi/router.go`
  (waves add domains here)
- `internal/db` — connection pool (unix socket default, TCP via
  `db_host`), embedded goose migrations, sqlc config + queries + `dbq`
  output
- `internal/jobs` — durable job queue (`jobs` table) + worker
- `web` — React + Mantine + Vite + TypeScript UI (embedded into the binary)
- `deploy/` — Dockerfile (Debian 13), dev compose, Podman quadlets;
  `deploy/virtualmin/` holds the production Virtualmin deployment
  (Apache vhosts, pod Quadlets, secrets layout, deploy.sh, ops docs —
  see its README)
- `api/openapi.yaml` — API skeleton (`/healthz` now, `/v1/*` documented
  placeholders)

## Quickstart (docker compose)

```sh
make dev-up          # mariadb -> migrate -> app + worker
curl localhost:8880/healthz
# {"status":"ok","version":"dev"}
```

`make dev-down` stops the stack; `make migrate` re-runs migrations.

Staff access (`/v1/admin/*` needs `users.is_platform_admin` + a full
session) is bootstrapped with the CLI — there is no self-serve staff
sign-up:

```sh
docker compose -f deploy/compose/docker-compose.yml run --rm app \
  admin create --email staff@demo.local
```

The generated password prints once; the staff user has no org membership
so login goes straight to a full session.

## Configuration

`/etc/sp-portal/portal.yaml` (override with `PORTAL_CONFIG_FILE`) plus
`PORTAL_*` env vars, in increasing precedence: defaults < file < env. Key
entries (env name = `PORTAL_` + upper(key)):

| key               | default                    | notes                                |
|-------------------|----------------------------|--------------------------------------|
| `http_addr`       | `:8080`                    | HTTP listen address                  |
| `db_name`/`db_user` | `portal`/`portal`        |                                      |
| `db_socket`       | `/run/mysqld/mysqld.sock`  | unix socket transport (default)      |
| `db_host`/`db_port` | ``/`3306`                | set db_host to switch to TCP         |
| `db_password`     |                            | dev convenience                      |
| `db_password_file`|                            | secret file, must be mode 0400/0600  |
| `storage_dir`     | `/var/lib/sp-portal`       | releases/, apt/, offline-bundles/, … |
| `worker_interval` | `1s`                       | job-worker poll                      |
| `public_base_url` | `http://localhost:8080`    | external base for emails/Stripe URLs |
| `auth_secret_file`|                            | session/TOTP/token key (ephemeral if unset) |
| `session_ttl`     | `336h`                     | session cookie lifetime              |
| `secure_cookies`  | `false`                    | set true behind TLS                  |
| `altcha_secret_file` |                         | sign-up ALTCHA key; unset = captcha off (dev bypass) |
| `trial_days` / `trial_max_machines` | `30`/`25` | sign-up trial                        |
| `past_due_grace`  | `336h`                     | past_due -> suspended (unpaid) window |
| `suspend_sweep_interval` | `1h`               | suspension sweep cadence             |
| `smtp_*` / `mail_from*` |                        | outbound mail; unset host = log sink |
| `stripe_*_file`   |                            | file-mounted Stripe secrets          |
| `stripe_price_*`  |                            | plan -> Stripe price ids             |
| `stripe_automatic_tax` | `false`               | Stripe Tax on checkout/invoices      |
| `licence_issuer_kid` | `dev-issuer-1`          | kid embedded in licence signatures   |
| `licence_signing_key_file` |                | base64 Ed25519 key/seed, 0400/0600; empty = embedded DEV key |
| `instauth_max_skew` | `10m`                    | SP-Ed25519 timestamp window          |
| `instauth_rate_limit_per_min` | `60`          | per-instance authed request limit    |
| `download_secret_file` |                       | HMAC key for signed download URLs (ephemeral if unset) |
| `download_url_ttl` | `15m`                       | signed download-URL lifetime         |
| `bundle_signing_key_file` |                    | base64 Ed25519 key/seed for .spb bundles; empty = licence issuer |
| `bundle_signing_kid` | `bundle-issuer-1`           | kid embedded in bundle signatures    |

Secret files (`db_password_file`, `auth_secret_file`, `altcha_secret_file`,
`smtp_password_file`, `stripe_secret_key_file`,
`stripe_webhook_secret_file`, `licence_signing_key_file`,
`download_secret_file`, `bundle_signing_key_file`) must be mode
`0400` or `0600`; values are never logged (the slog handler also redacts
sensitive keys). When `licence_signing_key_file` is unset the service
signs with the embedded **dev-only** issuer (`internal/licensing/devkey.go`)
— never ship that to production. The appliance contract (licence document
format, SP-Ed25519 auth scheme, activation/check-in flows) is specified in
`docs/fakeportal.md`.

## Accounts + billing (R5-3)

- `POST /v1/auth/signup` creates the user (Argon2id), org, owner
  membership, 30-day/25-machine trial subscription + licence and queues a
  verification email. ALTCHA bot protection is on when
  `altcha_secret_file` is set (dev leaves it unset — documented bypass).
- Sessions are httpOnly signed cookies (no session table); the signature
  is bound to the credential fingerprint so password/TOTP changes
  invalidate cookies. TOTP is optional for members, **required for
  owners**: new owners enrol before their first full session.
- `POST /stripe/webhook` verifies the signature, stores the event
  (idempotent on `event_id`) and enqueues a `billing.stripe_event` job;
  worker handlers drive the subscription state machine off event
  payloads. A `billing.suspend_sweep` job self-reschedules and suspends
  subscriptions past due beyond `past_due_grace` (schema's `unpaid`
  status — there is no `suspended` value) with an audit row + email.
- `/v1/billing/checkout|portal|invoices` need owner/admin org role; the
  Stripe client is bounded behind an interface (tests stub it).
- Dev mail goes to Mailpit (compose, UI on :8025); production points
  `smtp_*` at a relay and enqueues `mail.send` jobs.

## Development

```sh
make build         # web (Vite -> internal/webui/dist) + bin/sp-portal
make test          # go test ./... (integration tests use a throwaway mariadb container)
make lint          # gofmt + go vet + staticcheck, eslint for web/
make acceptance    # 1000 jobs / 2 worker replicas exactly-once test
```

Tests needing MariaDB start a throwaway `mariadb:11.4` container when
docker is on PATH, or reuse `SP_PORTAL_TEST_DSN` when set; they skip
otherwise (`-short` also skips).
