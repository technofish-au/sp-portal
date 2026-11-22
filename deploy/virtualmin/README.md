# Deploy & ops — sp-portal on Virtualmin (R5-7)

Concrete deploy configuration for the one known environment: **Virtualmin
Pro on Debian 13**, virtual server `serverperch.com`, domain user
`serverperch`, rootless Podman pod `sp-portal` running
`sp-portal-app` + `sp-portal-worker` from
`ghcr.io/technofish-au/sp-portal`.

```
deploy/virtualmin/
├── README.md                  ← this file (install order + reboot test)
├── apache/                    ← vhost examples to merge into the generated configs
│   ├── portal.serverperch.com.conf
│   ├── api.serverperch.com.conf       (LimitRequestBody 500 MB, ProxyTimeout 600)
│   └── admin.serverperch.com.conf     (Require ip staff allow-list)
├── podman/                    ← Quadlet units → ~/.config/containers/systemd/
│   ├── sp-portal.pod
│   ├── sp-portal-app.container
│   ├── sp-portal-worker.container
│   └── sp-portal-migrate.container    (one-shot alternative; deploy.sh uses podman run)
├── secrets/
│   ├── secrets.md             ← podman secret create commands + container split
│   └── secrets.list           ← canonical names (deploy.sh preflight reads this)
├── backups.md                 ← Virtualmin daily off-site backup + restore test
├── monitoring/                ← Uptime Kuma import + webhook-failure alerting
└── deploy.sh                  ← migrate → pod update → rsync site (has --dry-run)
```

The generic dev quadlets in `deploy/podman/` are a different target
(named volume, no pod) — do not mix the two sets.

## Operator install order

```bash
# 0. Virtualmin legs already done: virtual server + sub-servers exist,
#    MariaDB ≥ 10.6, webmin-virtualmin-podman installed (roadmap items 1–2).

# 1. Database users (Virtualmin → Edit Databases, or mysql as root):
#      sp_portal_app     — SELECT/INSERT/UPDATE/DELETE on serverperch.*
#      sp_portal_migrate — DDL privileges on serverperch.* (migrate only)
#    Charset utf8mb4 / utf8mb4_unicode_ci, STRICT_TRANS_TABLES.

# 2. As the serverperch user — storage + secrets + quadlets:
install -d -m 0755 ~/storage
install -d -m 0700 ~/.config/containers/systemd
cp podman/sp-portal.pod podman/sp-portal-app.container \
   podman/sp-portal-worker.container podman/sp-portal-migrate.container \
   ~/.config/containers/systemd/
# create the ten secrets — secrets/secrets.md
# fill in placeholders in sp-portal-app.container (smtp host, price_*
# ids, issuer kids)
systemctl --user daemon-reload

# 3. Boot persistence:
sudo loginctl enable-linger serverperch      # user services survive logout/reboot

# 4. First deploy (from anywhere with SSH access):
./deploy.sh --host <host> --user serverperch --tag latest --dry-run
./deploy.sh --host <host> --user serverperch --tag latest

# 5. Apache: merge the marked proxy blocks from apache/*.conf into the
#    Virtualmin-generated vhosts; a2enmod ssl proxy proxy_http headers rewrite;
#    apachectl configtest && systemctl reload apache2.
```

## Start on boot — Quadlets, and why not podman-restart.service

Rootless containers do not reliably come back on their own after a
reboot on the Virtualmin/Podman-plugin path (roadmap item 4 — a known
reported issue). Two mechanisms exist:

- **Quadlet units (what we ship).** systemd owns the lifecycle:
  `WantedBy=default.target` + `Restart=always` + `enable-linger` means
  the user manager starts at boot (linger makes it a real session) and
  the pod + both containers come up without a login. `systemctl --user
  status` is the obvious debugging surface and matches how the deploy
  script restarts the pod.
- **`podman-restart.service`** is the plugin's alternative: it replays
  `podman start` for containers created `--restart=always`. It works,
  but it only *restarts* what was already running and leaves containers
  whose restart state got lost; it also hides the pod topology. Keep it
  disabled when the Quadlets are enabled so the two managers don't race:
  `systemctl --user disable --now podman-restart.service`.

**Acceptance check (operator leg):** reboot the server; within 5 minutes
`curl https://api.serverperch.com/healthz` must be green and
`systemctl --user status sp-portal-app` active — no manual action.

## Deploy flow (TeamCity → deploy.sh)

`deploy.sh` is the script the TeamCity `sp-portal · Deploy`
configuration calls. It: pulls the tag, runs `sp-portal migrate` as a
`podman run --rm` one-off under the **DDL user** (`sp_portal_migrate`,
password via the `sp_portal_db_migrate_password` secret), restarts
`sp-portal-app`/`sp-portal-worker` via `systemctl --user` (Quadlet
units), rsyncs `site/dist/` to `public_html` (tar-over-ssh fallback when
rsync is missing locally), then checks `/healthz` on the pod port and
the public URL. `--dry-run` runs every read-only check (SSH, remote
tools, quadlets, all ten secrets, socket + storage paths) and prints the
plan without side effects.

`--pod-method virtualmin` exists for sites where the Podman plugin owns
the pod record: set `PORTAL_POD_UPDATE_CMD` to the plugin CLI command
(e.g. `virtualmin podman restart --domain serverperch.com sp-portal` —
check `virtualmin podman --help` on the installed plugin version); the
documented fallback is the default `systemd` method, which is always
correct for Quadlet-managed containers.

## Image

`deploy/docker/Dockerfile` builds one image; `serve`/`worker`/`migrate`
are subcommands selected by `Exec=` in the units / the migrate run. CI
(`sp-platform/.teamcity` PortalBuildTypes) pushes
`ghcr.io/technofish-au/sp-portal:sha-<commit>` and `:latest`; pin the
tag in the Quadlets for reproducible deploys.
