# Podman secrets layout — sp-portal on Virtualmin

All credentials are **Podman secrets** owned by the `serverperch` domain
user, mounted read-only into the containers at `/run/secrets/<name>`
with mode `0400`. They never appear in environment variables (which the
Virtualmin UI displays and `podman inspect` exposes). The app enforces
file mode `0400`/`0600` on every `*_file` setting (`internal/secrets`).

`secrets.list` in this directory is the canonical name list — the
Quadlets' `Secret=` lines and the `deploy.sh` preflight both use it.

## Create the secrets

Run **as the `serverperch` user** (rootless secrets live in the user's
secrets store, not the host's). `podman secret create` reads the secret
from a file; feed it with process substitution so the value never lands
on disk unencrypted — or use a throwaway file and `shred` it.

```bash
# One-time random keys (generate on the server):
podman secret create sp_portal_auth_secret    <(openssl rand -base64 32)
podman secret create sp_portal_altcha_secret  <(openssl rand -base64 32)
podman secret create sp_portal_download_secret <(openssl rand -base64 32)

# Database passwords — created when Virtualmin provisions the two DB
# users (see ../README.md "Database"):
podman secret create sp_portal_db_password         <(cat ~/.secrets/db_app)      # sp_portal_app
podman secret create sp_portal_db_migrate_password <(cat ~/.secrets/db_migrate)  # sp_portal_migrate

# Outbound mail (submission relay account):
podman secret create sp_portal_smtp_password <(cat ~/.secrets/smtp)

# Stripe Dashboard → Developers → API keys (secret key) and
# → Webhooks (endpoint signing secret, whsec_…):
podman secret create sp_portal_stripe_secret_key      <(cat ~/.secrets/stripe_key)
podman secret create sp_portal_stripe_webhook_secret  <(cat ~/.secrets/stripe_webhook)

# Ed25519 signing keys — base64 private key/seed, one per line, the same
# format sp-server release keys use. The licence key is generated and
# backed up offline in the R9 key ceremony; until then a throwaway key
# lets the deploy stand up:
openssl rand -base64 32 | podman secret create sp_portal_licence_signing_key -
openssl rand -base64 32 | podman secret create sp_portal_bundle_signing_key  -
```

Verify:

```bash
podman secret ls            # names must match secrets.list
podman secret inspect sp_portal_auth_secret   # shows metadata, not the value
```

Rotate a secret: `podman secret create` fails on existing names —
`podman secret rm <name>` then re-create, and restart the containers
(`systemctl --user restart sp-portal-app sp-portal-worker`).

## Which container gets what

| Secret | app | worker | migrate |
|---|---|---|---|
| `sp_portal_db_password` (DML user) | ✓ | ✓ | |
| `sp_portal_db_migrate_password` (DDL user) | | | ✓ |
| `sp_portal_auth_secret` (sessions/TOTP sealing) | ✓ | | |
| `sp_portal_altcha_secret` (sign-up PoW) | ✓ | | |
| `sp_portal_smtp_password` | ✓ | ✓ | |
| `sp_portal_stripe_secret_key` | ✓ | ✓ | |
| `sp_portal_stripe_webhook_secret` | ✓ | | |
| `sp_portal_download_secret` (HMAC `/dl/` URLs) | ✓ | | |
| `sp_portal_licence_signing_key` | ✓ | | |
| `sp_portal_bundle_signing_key` | ✓ | | |

The licence-signing key is mounted into **sp-portal-app only**
(09-release-roadmap.md R5 item 8) — the worker never needs it, and the
kid is rotated by the R9 key ceremony.

## Outside `public_html`

Podman secrets land under `$HOME/.local/share/containers/storage/secrets`
— inside the virtual-server home dir but outside `public_html`, so
Virtualmin file-manager/backup tooling handles them without exposing
them over HTTP. The alternative the roadmap allows — `0400` files under
e.g. `/home/serverperch/secrets/` — also works: point the
`PORTAL_*_FILE` env vars at the files and drop the `Secret=` lines.
Podman secrets are preferred: they surface in `podman secret ls` for
auditing and are mounted `type=mount` (tmpfs, never written to a layer).
