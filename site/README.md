# site/ — serverperch.com marketing site

Static [Astro](https://astro.build) site deployed to `public_html` on the
serverperch.com Virtualmin virtual server. No SSR, no backend, one small
vanilla-JS toggle (pricing billing period).

## Layout

| Path | Purpose |
|---|---|
| `src/pages/` | `/`, `/features`, `/pricing`, `/docs`, `/security`, `/contact`, `404` |
| `src/layouts/Base.astro` | Page shell: header nav, footer, meta/OG tags |
| `src/data/site.ts` | Portal URLs, trial terms, contact addresses — **edit here, not in markup** |
| `src/data/pricing.ts` | Licence tiers + prices (placeholder — update in this one file when pricing is final) |
| `src/styles/site.css` | Single global stylesheet, system font stack |
| `deploy.sh` | Build + rsync to the server (see below) |

## Develop

```sh
npm ci
npm run dev       # local dev server
npm run build     # production build -> dist/
npm run preview   # serve dist/ locally
```

Content conventions: no lorem ipsum, no invented testimonials or benchmarks,
portal URLs always come from `src/data/site.ts`, prices always from
`src/data/pricing.ts`.

## Deploy

```sh
./deploy.sh                          # build + rsync to the default target
./deploy.sh --dry-run                # build + rsync --dry-run (nothing written)
RSYNC_TARGET=user@host:path/ ./deploy.sh
```

- `RSYNC_TARGET` — rsync destination (default placeholder
  `serverperch@serverperch.com:public_html/`).
- `RSYNC_SSH` — extra ssh options, e.g. `RSYNC_SSH="-i ~/.ssh/deploy_key"`.
- `DRY_RUN=1` — same as `--dry-run`.

Rsync runs with `-azc --delete --itemize-changes`: checksum-based change
detection (CI checkouts have unreliable mtimes) and mirror semantics so stale
files are removed from `public_html`. The script is non-interactive — set up a
dedicated deploy key in the target user's `authorized_keys` for TeamCity.

## Updating prices

Edit `src/data/pricing.ts` only. Amounts are AUD cents (monthly and annual
figures are both explicit, so they don't have to be a clean multiple). Set
`PRICES_ARE_PLACEHOLDER = false` once list pricing is final to remove the
"provisional" notice.

## Linking to the portal

Purchase is not done on this site. Buy buttons link to the portal dashboard
(`PORTAL.root`); the portal's "Buy" button creates the Stripe Checkout
session. Sign-up/trial CTAs link to `PORTAL.signup`.
