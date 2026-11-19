# fakeportal — the sp-portal licence contract

This document is **the contract** between `sp-portal` and the ServerPerch
appliance. R6/R7/R8 (appliance agent, apt proxy, offline tooling) implement
against what is written here; if the implementation and this document ever
disagree, that is a bug — fix the code, not the doc.

Implemented by `internal/licensing` + `internal/instauth` (wave R5-2).

## Base URL and error envelope

All endpoints live under `/v1`. Errors are JSON:

```json
{ "error": "<machine_code>", "message": "<human readable>" }
```

`error` codes are stable API surface; `message` is diagnostic only.

## Cryptography

All signing is Ed25519 (RFC 8032). Base64 encodings on this page are
standard (RFC 4648, padding included) unless stated otherwise.

### Issuer keys and key rotation

Licence documents are signed by an *issuer key* identified by a `kid`
(key id). Verifiers hold a set of *verification keys* `{kid, alg,
public_key}` and accept a document when **any** entry in its
`signatures` array verifies — the array is the rotation slot: a second
issuer key can be introduced without invalidating documents or verifiers
that only know the first.

The development issuer is deliberately committed to the repo
(`internal/licensing/devkey.go`):

| field       | value                                                    |
|-------------|----------------------------------------------------------|
| kid         | `dev-issuer-1`                                           |
| public key  | `v5VfgN5NbooKyBIzKYTHdQIvh5wvjNiaeJe3BAaRc0Y=`             |

**DEV ONLY — never trusted by production appliances.** Production uses a
`licence_signing_key_file`-configured key with a distinct `kid`.

## Canonical JSON

Signatures over JSON documents cover the **canonical form** of the signed
member, a strict subset of RFC 8785 (JCS):

* object members sorted by key (all keys are ASCII snake_case, so JCS's
  UTF-16 ordering is plain byte order);
* no whitespace: `{"a":1,"b":[2,3]}`;
* strings escaped per JCS: `"` `\` and C0 controls only (`\b` `\f` `\n`
  `\r` `\t` or `\u00xx` lower-case hex). `<`, `>`, `&` are **not** escaped
  (unlike Go's `encoding/json` default);
* numbers are non-negative integers below 2^53, serialised in decimal —
  the format forbids fractional/exponent numbers;
* `true`, `false`, `null` as usual.

Verifying a document means: parse the envelope → re-canonicalise the
`licence` member → verify `signatures[i].sig` over those exact bytes.

## The licence document

```json
{
  "licence": {
    "v": 1,
    "licence_id": "018f3c…",
    "licence_key": "SPL-…",
    "org_id": "018f3c…",
    "instance_id": "<appliance-supplied stable id>",
    "kind": "subscription",
    "plan": "pro",
    "max_instances": 5,
    "features": ["monitoring", "apt-updates", "fleet"],
    "issued_at": "2026-01-02T03:04:05Z",
    "expires_at": "2027-01-02T00:00:00Z"
  },
  "signatures": [
    { "kid": "dev-issuer-1", "alg": "Ed25519", "sig": "<base64 64-byte sig>" }
  ]
}
```

* `sig` is Ed25519 over `canonical(licence)` — **not** over the raw bytes
  of the `licence` member; canonicalisation is what lets any JSON writer
  produce a verifiable document.
* `expires_at` may be `null` (perpetual/trial licences without expiry).
* `v` is the payload schema version (`1`); unknown fields must be ignored
  by verifiers but are still signed.
* Any tampering — reordering is fine, changing any value is not —
  invalidates the signature.

## SP-Ed25519 instance authentication

`POST /v1/check-ins` and `GET /v1/licence` are instance-authed. The
appliance holds an Ed25519 keypair generated at first boot; activation
binds its public key to its `instances.id`.

### String to sign

```
SP-ED25519-V1\n
<METHOD>\n          upper-case HTTP method, e.g. POST
<path>\n            request-target path exactly as sent, no query string
<ts>\n              unix seconds, decimal
<nonce>\n           opaque client nonce, ≤128 chars — MUST be unique per request
<body-sha256>\n     lower-case hex SHA-256 of the raw request body
                    (SHA-256 of the empty string for GET/empty bodies)
```

Each line including the last is `\n`-terminated. The signature is Ed25519
over the UTF-8 bytes of that string.

### Authorization header

```
Authorization: SP-Ed25519 instance="<instances.id>",
               key="<base64 32-byte public key>",
               ts="<unix seconds>",
               nonce="<nonce>",
               sig="<base64 64-byte signature>"
```

* `key` must equal the key bound at activation — the portal rejects with
  `wrong_key` otherwise. Sending the key on every request is what makes
  the clone signal explicit and leaves room for signed key rotation.
* `ts` must be within ±10 minutes of server time (`stale_timestamp`).
* `(instance, sig)` is checked against a replay cache (`replay`). A
  retry MUST generate a fresh nonce — replaying an identical signature is
  rejected even inside the window.
* Per-instance rate limit: 60 authenticated requests/minute (`429` +
  `Retry-After`).

### Auth error codes

`bad_auth_header` (400-level parse failure → 401), `rate_limited` (429),
`stale_timestamp`, `unknown_instance`, `no_key_bound`, `wrong_key`,
`body_too_large` (413), `bad_signature`, `replay` — all 401 unless noted.

## Endpoints

### POST /v1/activations — online activation (unauthenticated)

```json
{
  "licence_key": "SPL-…",
  "instance_id": "sha256-of-/etc/machine-id",
  "public_key": "<base64 appliance pubkey>",
  "name": "rack-4-monitor",            // optional, ≤200 chars
  "appliance_version": "1.4.0"         // optional, ≤64 chars
}
```

`instance_id` is the appliance's stable machine identity (the portal
stores it as `instances.fingerprint`, unique per organisation). `201`:

```json
{
  "instance": {
    "id": "<instances.id — used in the Authorization header>",
    "instance_id": "sha256-of-/etc/machine-id",
    "name": "rack-4-monitor",
    "status": "active",
    "suspected_clone": false
  },
  "licence": { "<licence document as above>" },
  "apt_credentials": { "username": "<instances.id>", "password": "spapt_…" }
}
```

* Re-activating the same `instance_id` with the same key is idempotent
  (re-issues the document).
* Re-activating with a **different** key flags the instance
  `suspected_clone` — the original key stays bound (the real appliance
  keeps working and sees the flag at check-in). Activation is **not**
  blocked; the appliance flow decides what to do with the flag.
* Errors: `400 bad_request`, `404 unknown_licence_key`, `403` licence
  revoked/expired, `409 seat_limit` (would exceed `max_instances`).

### POST /v1/check-ins — periodic report (SP-Ed25519)

Body is free-form appliance JSON; recognised fields:

```json
{ "appliance_version": "1.4.0",
  "reported_at": "2026-01-02T03:04:05Z",   // optional; defaults to server time
  "agents": { "count": 12 }, "metrics": { } // anything else is stored verbatim
}
```

`200`:

```json
{
  "status": "active",
  "licence": { "<freshly-signed licence document>" },
  "messages": [ { "code": "suspected_clone", "message": "…" } ],
  "latest_release": { "version": "1.4.2", "channel": "stable",
                      "published_at": "…" },
  "entitled_updates": true
}
```

`status` ∈ `active | suspected_clone | suspended | decommissioned |
expired | revoked` (`suspected_clone` wins when flagged). `messages`
carries machine-readable advisories — `suspected_clone`,
`licence_expiring`, `licence_expired`, `licence_revoked`,
`instance_suspended`, `instance_decommissioned`. `latest_release` is
`null` when nothing is published; `entitled_updates` is false when the
licence is expired/revoked.

### GET /v1/licence — current licence (SP-Ed25519)

`200`: `{ "status", "licence": <document|null>, "messages": [...] }` —
the same shape as check-in minus release/report side effects.

### POST /v1/offline/activations — air-gapped bundle (customer-auth)

Produces a downloadable bundle for appliances that never reach the
portal. **Auth stub**: until the accounts wave lands session auth, the
credential is `org_id` + `licence_key` — the handler verifies the licence
belongs to the org. To be replaced by session/org-membership auth.

```json
{ "org_id": "018f3c…", "licence_key": "SPL-…",
  "instance_id": "…", "public_key": "<optional — bound if sent>" }
```

`201`, `Content-Disposition: attachment; filename="serverperch-licence-<instance_id>.json"`:

```json
{ "bundle_version": 1,
  "instance": { …as above… },
  "licence": { "<licence document>" },
  "verification_keys": [ { "kid": "dev-issuer-1", "alg": "Ed25519",
                           "public_key": "<base64>" } ],
  "apt_credentials": { "username": "…", "password": "spapt_…" } }
```

An air-gapped appliance verifies `licence` against `verification_keys`
exactly as the online flow — canonicalise, pick the signature slot whose
`kid` it trusts, verify.

## Clone detection

Two different `public_key`s presenting the same `instance_id` means the
appliance image (including its machine id) was cloned. Activation flags
the instance `suspected_clone` (durable, idempotent) without blocking;
check-ins then report `status: "suspected_clone"` plus a `suspected_clone`
message. The originally-bound key remains authoritative — a clone that
cannot produce the original key cannot authenticate, which is the
mechanism doing the blocking, not the flag.
