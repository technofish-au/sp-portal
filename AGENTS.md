# sp-portal agent instructions

ServerPerch customer portal: Go + chi + MariaDB + React/Mantine. This repo
is a submodule of `serverperch` (`git@github.com:technofish-au/sp-portal`)
and is **not** part of the root `go.work` — every Go command needs
`GOWORK=off` (the Makefile exports it; use it for ad-hoc `go`/`sqlc` runs
too).

## Verify before finishing

- `./scripts/ensure-web-dist.sh` first — `//go:embed all:dist` needs
  `internal/webui/dist/index.html` to exist.
- `GOWORK=off go build ./...` and `GOWORK=off go vet ./...` clean.
- `GOWORK=off go test ./...` green; DB tests start a throwaway
  `mariadb:11.4` docker container (or honour `SP_PORTAL_TEST_DSN`) and
  skip when unavailable.
- `make lint` (gofmt + vet + staticcheck; eslint when `web/node_modules`
  exists).
- `cd web && npx tsc --noEmit` green; regenerate `src/routeTree.gen.ts`
  via `npm run build` after editing `src/routes/`.
- Compose smoke: `make dev-up` → `curl localhost:8080/healthz` → `make dev-down`.

## Conventions (mirroring sp-platform)

- Config: koanf, `/etc/sp-portal/portal.yaml` + `PORTAL_*` env; secrets are
  file-mounted (mode 0400/0600 enforced) and never logged —
  `internal/logging` redacts sensitive slog keys.
- IDs: UUID text `CHAR(36)` (uuid v7 via `uuid.Must(uuid.NewV7())`).
- Timestamps: UTC; columns `DATETIME(6)` defaulting
  `CURRENT_TIMESTAMP(6)`, queries use `UTC_TIMESTAMP(6)`.
- Migrations: forward-only goose SQL in `internal/db/migrations/NNNNN_*.sql`
  (no `+goose Down` — sqlc replays the directory), InnoDB + utf8mb4.
- Queries: sqlc (`internal/db/queries/*.sql` → `internal/db/dbq`) for
  domain reads/writes; the job queue uses plain `database/sql` because it
  needs `FOR UPDATE SKIP LOCKED` and per-statement transaction control.
- Domains live in `internal/<domain>/routes.go`; registering one is a
  single `r.Mount` line under `/v1` in `internal/httpapi/router.go`.
- Jobs: `jobs` table with `kind`+`payload`+unique `dedupe_key`,
  `attempts`/`max_attempts` backoff, terminal `dead`; transient InnoDB
  deadlocks (1213/1205) are retried — keep statements single-statement and
  replayable.
