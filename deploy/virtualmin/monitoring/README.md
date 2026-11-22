# External health monitoring — sp-portal (R5-7)

Single-server deployment: an *external* monitor is the alert path —
if the host is down, only something off-box can notice.
(09-release-roadmap.md R5 item 13.)

## Monitors (any HTTP-check service works; Uptime Kuma shown)

`uptime-kuma.json` is an Uptime Kuma backup-format file —
**Settings → Backup → Import** creates the three monitors:

| Monitor | Check | Interval |
|---|---|---|
| `sp-portal api healthz` | `GET https://api.serverperch.com/healthz` → 200 | 60 s |
| `sp-portal portal SPA` | keyword `<div id="root">` on `https://portal.serverperch.com/` | 300 s |
| `sp-portal TLS expiry` | same URL, cert-expiry notification on | 3600 s |

Wire notifications in **Settings → Notifications** (mail/ntfy/webhook —
the Virtualmin host's Postfix submission relay works for SMTP
notifications, but prefer a path that survives the host being down).

Equivalent elsewhere: any HTTP(S) keyword monitor on
`https://api.serverperch.com/healthz` expecting `{"status":"ok"}` is
sufficient — Uptime Kuma, HetrixTools, healthchecks.io (ping-style:
have the monitor *fetch* the URL, not wait for a push).

## Stripe webhook failure alerting

The portal's webhook handler (`/stripe/webhook` on api.) answers 2xx as
soon as the event is verified, stored and a job enqueued — Stripe sees
healthy deliveries even when the *processing* fails later, so watch both
sides:

1. **Stripe-side (deliveries).** Stripe Dashboard → **Developers →
   Webhooks → your endpoint** shows delivery failures; enable
   **Settings → Notifications → "Webhook errors"** emails, and point the
   webhook endpoint's monitor (above) alert at the on-call channel —
   repeated non-2xx deliveries also show as repeated `5xx`/`4xx` in the
   Stripe dashboard graph.
2. **App-side (processing).** A job that fails all retries lands in
   `jobs` with `status=dead` and mails the platform admins (the worker
   alerts by email on dead jobs — roadmap item 6). Staff admin shows the
   dead queue; a dead `stripe_event` job is the "webhook failed" signal.

## What monitors do NOT cover

- Pod running but app wedged with a stale-schema DB — `serve` exits and
  the unit restart-loops; the healthz monitor catches the resulting
  outage, `journalctl --user -u sp-portal-app` has the reason.
- Worker liveness has no HTTP probe (by design). The dead-jobs mail is
  the operator-visible failure signal.
