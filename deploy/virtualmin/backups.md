# Virtualmin backups — serverperch.com (R5-7)

Roadmap requirement (09-release-roadmap.md R5 item 11): daily off-site
Virtualmin scheduled backups of the `serverperch.com` virtual server —
home directory (which includes `storage/`), the MariaDB `serverperch`
database and the virtual-server config — 30-day retention, quarterly
restore test. This is operator work; this file is the config to apply.

## What a Virtualmin virtual-server backup covers

A virtual-server backup of `serverperch.com` (plus sub-servers
`portal.`/`api.`/`admin.` — they belong to the same virtual server and
are included by "all servers"/sub-server flags) includes:

- **Home directory** `/home/serverperch` — including `storage/`
  (releases/, apt/, offline-bundles/, support-bundles/, exports/) and
  `public_html` (the marketing site). `storage/` is the big item —
  releases are a few GB each; see "size" below.
- **MariaDB database** `serverperch` — dumped by Virtualmin per-domain.
- **Virtual-server config** — DNS records, Apache vhosts, Let's Encrypt
  renewal hooks, mail config.

NOT covered by the domain backup — capture separately:

- **Podman secrets** (`~/.local/share/containers/storage/secrets`) —
  actually inside the home dir, so the domain backup does pick them up,
  but keep the **licence-signing key** in the R9 offline backup too
  (losing it means re-issuing every licence).
- **Quadlet units** (`~/.config/containers/systemd/`) — inside the home
  dir, so included; re-running the install block in README.md also
  regenerates them from this repo.
- **The container image** — re-pull `ghcr.io/technofish-au/sp-portal`
  after restore; do not back up `~/.local/share/containers/storage`
  image layers (excluded below — they're tens of GB and reproducible).

## Schedule (Virtualmin UI)

Virtualmin → **Backup and Restore → Scheduled Backups → Add a new
backup schedule**:

| Setting | Value |
|---|---|
| Virtual servers | `serverperch.com` + sub-servers |
| Features | all (home dir, databases, Virtualmin config, DNS) |
| Destination | see below |
| Schedule | daily, off-peak (e.g. 02:30) |
| Retention | **keep 30 days** of backups ("Delete old backups: after 30 days") |
| Exclude | `/home/serverperch/.local/share/containers/storage` (image layers) |

### Destination — S3-compatible

`s3://<key>:<secret>@<bucket>/serverperch/%Y-%m-%d` — strftime naming
gives one object set per day; retention deletes the dated dirs past 30
days. Virtualmin → Backup and Restore → Cloud Storage Providers holds
the S3 credentials.

### Destination — rsync/SSH target (alternative)

`ssh://backup@<host>/srv/backups/serverperch/%Y-%m-%d` — Virtualmin uses
rsync over SSH; install the backup host's key for the domain owner and
keep the target on a different failure domain.

## CLI equivalent

```bash
virtualmin backup-domain --domain serverperch.com \
  --all-features \
  --dest 's3://<key>:<secret>@<bucket>/serverperch/' \
  --strftime \
  --except-dir '.local/share/containers/storage' \
  --purge 30
# --schedule via: virtualmin create-scheduled-backup --dest … --all-features …
```

## Size note

`storage/` grows by ~3 release artifacts × GB per release. Keep the
latest + previous supported versions and prune with the staff action —
or the daily backup window and off-site transfer grow without bound.
If the backup transfer becomes the constraint, split the schedule:
nightly `serverperch` DB + config + `public_html`, weekly `storage/`.

## Quarterly restore test (acceptance: restored portal serves licences)

On a scratch Virtualmin server (same Debian 13, MariaDB ≥ 10.6):

1. `virtualmin restore-domain --domain serverperch.com --all-features --source <backup>`
2. Re-create the podman secrets per secrets/secrets.md (they are in the
   backup, but re-creating proves the ceremony still works) — or verify
   the restored `~/.local/share/containers/storage/secrets/filesystems`.
3. Reinstall the Quadlets (`deploy/virtualmin/podman/*` →
   `~/.config/containers/systemd/`), `systemctl --user daemon-reload`,
   `loginctl enable-linger serverperch`, pull the image.
4. `systemctl --user start sp-portal-app sp-portal-worker`; run
   `sp-portal migrate status` (one-off container) — must show the
   restored schema at current version.
5. Acceptance probes:
   - `curl -fsS https://api.serverperch.com/healthz` (scratch DNS/hosts)
   - portal login works; a licence row from the restored DB renders
   - a signed download URL for a restored release artifact streams
     (http.ServeContent + range request works — `curl -r 0-1` returns 206)
6. Record the test date + outcome; destroy the scratch server.
