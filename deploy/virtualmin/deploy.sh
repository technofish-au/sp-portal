#!/usr/bin/env bash
# deploy.sh — deploy sp-portal to the Virtualmin host (R5-7).
#
# Order of operations (09-release-roadmap.md R5 item 12):
#   1. preflight — SSH up, remote tooling present, secrets + quadlets
#      installed (read-only checks)
#   2. pull the image tag
#   3. migrate — `sp-portal migrate` as a one-off container with the DDL
#      user (sp_portal_migrate + sp_portal_db_migrate_password secret)
#   4. pod update — restart app+worker (systemd quadlets by default;
#      Virtualmin Podman plugin CLI when --pod-method virtualmin and
#      PORTAL_POD_UPDATE_CMD names the command)
#   5. rsync the marketing site (site/dist) into public_html
#   6. health check — pod port on the host, then the public endpoint
#
# No secrets pass through this script: remote Podman secrets are
# referenced by name, SSH comes from agent flags/key files.
#
# Usage:
#   deploy.sh --host portal.example.com [--user serverperch]
#             [--image ghcr.io/technofish-au/sp-portal] [--tag latest]
#             [--site-dir <repo>/site/dist] [--skip-site]
#             [--pod-method systemd|virtualmin] [--dry-run]
#             [--identity ~/.ssh/deploy_key] [--port 22]
#             [--health-url https://api.serverperch.com/healthz] [--skip-health]
#
# TeamCity calls this non-interactively; every value is an env var too:
#   PORTAL_DEPLOY_HOST PORTAL_DEPLOY_USER PORTAL_SSH_PORT
#   PORTAL_SSH_IDENTITY PORTAL_IMAGE PORTAL_IMAGE_TAG PORTAL_SITE_DIR
#   PORTAL_REMOTE_HTML PORTAL_POD_METHOD PORTAL_POD_UPDATE_CMD
#   PORTAL_HEALTH_URL PORTAL_DRY_RUN=1
#   PORTAL_SSH_CMD    — full ssh binary+flags override (test hooks only)

set -euo pipefail

# ---------------------------------------------------------------- args ---

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SELF_DIR/../.." && pwd)"

HOST="${PORTAL_DEPLOY_HOST:-}"
REMOTE_USER="${PORTAL_DEPLOY_USER:-serverperch}"
SSH_PORT="${PORTAL_SSH_PORT:-22}"
SSH_IDENTITY="${PORTAL_SSH_IDENTITY:-}"
IMAGE="${PORTAL_IMAGE:-ghcr.io/technofish-au/sp-portal}"
TAG="${PORTAL_IMAGE_TAG:-latest}"
SITE_DIR="${PORTAL_SITE_DIR:-$REPO_ROOT/site/dist}"
REMOTE_HTML="${PORTAL_REMOTE_HTML:-}"
POD_METHOD="${PORTAL_POD_METHOD:-systemd}"
POD_UPDATE_CMD="${PORTAL_POD_UPDATE_CMD:-}"
HEALTH_URL="${PORTAL_HEALTH_URL:-https://api.serverperch.com/healthz}"
DRY_RUN="${PORTAL_DRY_RUN:-}"
SKIP_SITE=""
SKIP_HEALTH=""
SECRETS_LIST="${PORTAL_SECRETS_LIST:-$SELF_DIR/secrets/secrets.list}"

usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --host)        HOST="$2"; shift 2;;
        --user)        REMOTE_USER="$2"; shift 2;;
        --port)        SSH_PORT="$2"; shift 2;;
        --identity)    SSH_IDENTITY="$2"; shift 2;;
        --image)       IMAGE="$2"; shift 2;;
        --tag)         TAG="$2"; shift 2;;
        --site-dir)    SITE_DIR="$2"; shift 2;;
        --remote-html) REMOTE_HTML="$2"; shift 2;;
        --pod-method)  POD_METHOD="$2"; shift 2;;
        --health-url)  HEALTH_URL="$2"; shift 2;;
        --skip-site)   SKIP_SITE=1; shift;;
        --skip-health) SKIP_HEALTH=1; shift;;
        --dry-run|--check) DRY_RUN=1; shift;;
        -h|--help)     usage; exit 0;;
        *) echo "deploy.sh: unknown argument: $1" >&2; usage; exit 2;;
    esac
done

if [ -z "$HOST" ]; then
    echo "deploy.sh: --host (or PORTAL_DEPLOY_HOST) is required" >&2
    exit 2
fi

# ------------------------------------------------------------- helpers ---

# SSH command: PORTAL_SSH_CMD overrides everything (test hooks — the
# override owns ALL flags). Otherwise ssh + optional identity/port.
if [ -n "${PORTAL_SSH_CMD:-}" ]; then
    SSH_BASE="$PORTAL_SSH_CMD"
else
    SSH_BASE="ssh -o BatchMode=yes -o ConnectTimeout=10"
    if [ -n "$SSH_IDENTITY" ]; then SSH_BASE="$SSH_BASE -i $SSH_IDENTITY"; fi
    SSH_BASE="$SSH_BASE -p $SSH_PORT"
fi
SSH_TARGET="$REMOTE_USER@$HOST"

step() { printf '\n== %s\n' "$*"; }
# run REMOTE <cmd...> — execute on the host (or echo under --dry-run).
remote() {
    if [ -n "$DRY_RUN" ]; then
        echo "DRY-RUN ssh $SSH_TARGET: $*"
        return 0
    fi
    $SSH_BASE "$SSH_TARGET" "$@"
}
# probe REMOTE <cmd...> — read-only remote check; runs even in dry-run
# (that is the point of --dry-run: validate the connectivity picture).
probe() {
    $SSH_BASE "$SSH_TARGET" "$@"
}

REMOTE_HOME="/home/$REMOTE_USER"
[ -z "$REMOTE_HTML" ] && REMOTE_HTML="$REMOTE_HOME/public_html"

MIGRATE_ENV="PORTAL_DB_SOCKET=/run/mysqld/mysqld.sock \
PORTAL_DB_NAME=serverperch PORTAL_DB_USER=sp_portal_migrate \
PORTAL_DB_PASSWORD_FILE=/run/secrets/sp_portal_db_migrate_password"

# ----------------------------------------------------------- preflight ---

step "preflight: $SSH_TARGET (host=$HOST user=$REMOTE_USER port=$SSH_PORT)"

echo "-- ssh connectivity"
probe true </dev/null

echo "-- remote tools"
probe 'for c in podman systemctl; do command -v "$c" >/dev/null \
    || { echo "missing: $c"; exit 1; }; done; \
    command -v rsync >/dev/null || command -v tar >/dev/null' </dev/null

echo "-- quadlet units installed (sp-portal{,-app,-worker,-migrate})"
probe 'systemctl --user list-unit-files --no-legend 2>/dev/null | \
    grep -q "^sp-portal-app.service" || \
    ls ~/.config/containers/systemd/ 2>/dev/null | grep -q "^sp-portal-app.container" \
    || { echo "quadlet units not installed — see deploy/virtualmin/README.md"; exit 1; }' </dev/null

echo "-- podman secrets present"
missing=0
while read -r line; do
    name="$(echo "$line" | awk '{print $1}')"
    case "$name" in ''|\#*) continue;; esac
    if ! probe "podman secret exists $name" </dev/null >/dev/null 2>&1; then
        echo "   MISSING secret: $name (create per secrets/secrets.md)"
        missing=1
    fi
done < "$SECRETS_LIST"
[ "$missing" -eq 0 ] || { echo "deploy.sh: missing podman secrets" >&2; exit 1; }

echo "-- storage + socket mounts exist"
probe 'test -d /home/serverperch/storage -o -d ~/storage; \
    test -S /run/mysqld/mysqld.sock' </dev/null

echo "-- podman can reach the registry"
if [ -z "$DRY_RUN" ]; then
    remote "podman pull $IMAGE:$TAG"
else
    echo "DRY-RUN: would run on host: podman pull $IMAGE:$TAG"
fi

if [ -n "$DRY_RUN" ]; then
    cat <<EOF

DRY-RUN plan (nothing executed):
  migrate : podman run --rm $IMAGE:$TAG migrate \\
              (env: $MIGRATE_ENV) \\
              -v /run/mysqld:/run/mysqld:ro \\
              --secret sp_portal_db_migrate_password,type=mount,mode=0400
  pod     : method=$POD_METHOD $( [ "$POD_METHOD" = systemd ] && \
              echo "systemctl --user restart sp-portal-pod && start sp-portal-app sp-portal-worker" \
              || echo "PORTAL_POD_UPDATE_CMD=${POD_UPDATE_CMD:-<unset — REQUIRED for virtualmin method>}")
  site    : rsync ${SITE_DIR}/ -> $SSH_TARGET:$REMOTE_HTML/ \
$( [ -d "$SITE_DIR" ] || echo "            (SKIPPED — $SITE_DIR does not exist; R5-6 site/ not merged yet)")
  health  : remote http://127.0.0.1:8080/healthz then $HEALTH_URL
EOF
    echo
    echo "deploy.sh: dry-run checks passed for $SSH_TARGET"
    exit 0
fi

# ------------------------------------------------------------- migrate ---

step "migrate: $IMAGE:$TAG (DDL user sp_portal_migrate)"
# --user 0 matches the Quadlet units: rootless container-root maps to
# the domain user, which is what can read the root-only 0400 secret
# mounts (the image's own USER is 10001).
remote "podman run --rm --name sp-portal-migrate --user 0 \
    --secret sp_portal_db_migrate_password,type=mount,mode=0400 \
    -v /run/mysqld:/run/mysqld:ro \
    -e PORTAL_DB_SOCKET=/run/mysqld/mysqld.sock \
    -e PORTAL_DB_NAME=serverperch \
    -e PORTAL_DB_USER=sp_portal_migrate \
    -e PORTAL_DB_PASSWORD_FILE=/run/secrets/sp_portal_db_migrate_password \
    $IMAGE:$TAG migrate" </dev/null

# ---------------------------------------------------------- pod update ---

step "pod update (method=$POD_METHOD)"
case "$POD_METHOD" in
    systemd)
        # Restart the POD service, then start the containers: the quadlet
        # pod is created --exit-policy=stop, so it tears itself down the
        # moment its last container exits — `restart sp-portal-app
        # sp-portal-worker` (containers first) loses the pod mid-flight
        # and fails with dependency errors. Restarting the pod cascades
        # the container stop via BindsTo, recreates the pod-id, then the
        # containers start fresh against the new image.
        remote "systemctl --user daemon-reload && \
            systemctl --user restart sp-portal-pod.service && \
            systemctl --user start sp-portal-app.service sp-portal-worker.service" </dev/null
        ;;
    virtualmin)
        # The Virtualmin Podman plugin CLI manages the pod record the UI
        # shows. The exact subcommand is plugin-version dependent —
        # operators set PORTAL_POD_UPDATE_CMD to the full remote command,
        # e.g. 'virtualmin podman restart --domain serverperch.com sp-portal'.
        # Fallback is always --pod-method systemd.
        [ -n "$POD_UPDATE_CMD" ] || {
            echo "deploy.sh: --pod-method virtualmin needs PORTAL_POD_UPDATE_CMD" >&2
            exit 2
        }
        remote "$POD_UPDATE_CMD" </dev/null
        ;;
    *)
        echo "deploy.sh: unknown --pod-method '$POD_METHOD' (systemd|virtualmin)" >&2
        exit 2;;
esac

# ---------------------------------------------------------------- site ---

if [ -n "$SKIP_SITE" ]; then
    step "site: skipped (--skip-site)"
elif [ ! -d "$SITE_DIR" ]; then
    step "site: skipped ($SITE_DIR absent — R5-6 site/ not in this checkout)"
else
    step "site: $SITE_DIR/ -> $SSH_TARGET:$REMOTE_HTML/"
    if command -v rsync >/dev/null; then
        RSYNC_SSH="$SSH_BASE"
        # shellcheck disable=SC2086
        rsync -az --delete -e "$RSYNC_SSH" "$SITE_DIR/" "$SSH_TARGET:$REMOTE_HTML/"
    else
        echo "rsync not installed locally — falling back to tar over ssh"
        # shellcheck disable=SC2086
        tar -C "$SITE_DIR" -cf - . | $SSH_BASE "$SSH_TARGET" "tar -C $REMOTE_HTML -xf -"
    fi
fi

# -------------------------------------------------------------- health ---

if [ -n "$SKIP_HEALTH" ]; then
    step "health: skipped (--skip-health)"
else
    step "health: pod port on host"
    remote 'sleep 3; curl -fsS -m 15 http://127.0.0.1:8080/healthz' </dev/null
    step "health: $HEALTH_URL"
    curl -fsS -m 15 "$HEALTH_URL" </dev/null
    echo
fi

step "deploy complete: $IMAGE:$TAG on $SSH_TARGET"
