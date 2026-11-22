#!/usr/bin/env bash
# deploy.sh — build the ServerPerch marketing site and rsync it to the
# Virtualmin virtual server's public_html.
#
# Non-interactive by design (runs from TeamCity). Configuration is via
# environment variables only — no prompts.
#
#   RSYNC_TARGET   rsync destination, e.g. user@host:public_html/
#                  (default: placeholder below — override in CI)
#   RSYNC_SSH      extra ssh options, e.g. "-i /path/to/deploy_key -p 22"
#                  (default: none — relies on ssh config / agent)
#   DRY_RUN        set to 1, or pass --dry-run / -n, to print the rsync
#                  command and run it with --dry-run instead of deploying.
#
# Usage:
#   ./deploy.sh              # build + deploy
#   ./deploy.sh --dry-run    # build + rsync --dry-run (nothing is written)
#   DRY_RUN=1 ./deploy.sh    # same
set -euo pipefail

cd "$(dirname "$0")"

RSYNC_TARGET="${RSYNC_TARGET:-serverperch@serverperch.com:public_html/}"
RSYNC_SSH="${RSYNC_SSH:-}"
DRY_RUN="${DRY_RUN:-0}"

for arg in "$@"; do
  case "$arg" in
    --dry-run|-n) DRY_RUN=1 ;;
    --help|-h)
      sed -n '2,22p' "$0"
      exit 0
      ;;
    *)
      echo "deploy.sh: unknown argument '$arg'" >&2
      exit 2
      ;;
  esac
done

echo "==> Building site"
npm ci --no-audit --no-fund
npm run build

DIST="dist/"
if [[ ! -f "${DIST}index.html" ]]; then
  echo "deploy.sh: build produced no ${DIST}index.html" >&2
  exit 1
fi

# rsync flags:
#   -a            archive (recursive, preserves times/perms/symlinks)
#   -c            checksum-based change detection (file mtimes from CI
#                 checkouts are unreliable)
#   --delete      remove files on the target that are gone from dist/
#   -z            compress in transit
#   --itemize-changes  log what changed (useful in CI logs)
RSYNC_ARGS=(-azc --delete --itemize-changes --human-readable)

if [[ -n "$RSYNC_SSH" ]]; then
  # Intentionally word-split: RSYNC_SSH may carry several ssh options.
  # shellcheck disable=SC2086
  RSYNC_ARGS+=(-e "ssh $RSYNC_SSH")
fi

if [[ "$DRY_RUN" == "1" ]]; then
  RSYNC_ARGS+=(--dry-run)
  echo "==> DRY RUN — no files will be written"
fi

echo "==> rsync ${RSYNC_ARGS[*]} ${DIST} ${RSYNC_TARGET}"
rsync "${RSYNC_ARGS[@]}" "$DIST" "$RSYNC_TARGET"

echo "==> Done"
