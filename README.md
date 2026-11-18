# sp-portal

serverperch.com — the customer portal + licensing backend for the
ServerPerch on-prem monitoring appliance. Go service (chi + MariaDB +
embedded goose migrations + a SKIP LOCKED job queue) with a React/Mantine
web UI.

## Layout

- `cmd/sp-portal` — single binary: `serve`, `worker`, `migrate`,
  `healthcheck`, `version`
- `internal/<domain>` — one package per domain; each exposes `routes.go`
  mounted with a single `r.Mount` line in `internal/httpapi/router.go`
  (waves add domains here)
- `internal/db` — connection pool (unix socket default, TCP via
  `db_host`), embedded goose migrations, sqlc config + queries + `dbq`
  output
- `internal/jobs` — durable job queue (`jobs` table) + worker
- `web` — React + Mantine + Vite + TypeScript UI (embedded into the binary)
- `deploy/` — Dockerfile (Debian 13), dev compose, Podman quadlets
- `api/openapi.yaml` — API skeleton (`/healthz` now, `/v1/*` documented
  placeholders)

## Quickstart (docker compose)

```sh
make dev-up          # mariadb -> migrate -> app + worker
curl localhost:8080/healthz
# {"status":"ok","version":"dev"}
```

`make dev-down` stops the stack; `make migrate` re-runs migrations.

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
| `stripe_*_file`   |                            | file-mounted Stripe secrets          |

Secret files (`db_password_file`, `stripe_secret_key_file`,
`stripe_webhook_secret_file`) must be mode `0400` or `0600`; values are
never logged (the slog handler also redacts sensitive keys).

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
