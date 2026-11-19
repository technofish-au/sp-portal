# Offline update bundles — `.spb` signed tarball format (v1)

Implemented by `internal/bundles` + the staff generator
`POST /v1/admin/releases/{id}/offline-bundle` (wave R5-4). This document
is the format spec; when code and doc disagree the code is wrong.

## Purpose

Air-gapped appliances cannot reach the portal or the apt repository. A
bundle carries a release artifact plus the metadata needed to decide
whether it may be applied, signed so the appliance can verify
provenance against its trust anchors before unpacking.

## Container

A `.spb` file is a **gzip-compressed tar** archive. Member names:

| member        | content                                              |
|---------------|------------------------------------------------------|
| `MANIFEST`    | JSON manifest (below) — the signed bytes             |
| `SIGNATURE`   | JSON signature envelope (below)                      |
| `payload/…`   | one member per manifest `files[]` entry              |

Payload members are regular files; their tar name is `payload/` + the
`path` from the manifest entry (e.g. `payload/sp-platform_1.4.2.tar.gz`).

## MANIFEST

UTF-8 JSON object:

```json
{
  "v": 1,
  "kind": "sp-offline-bundle",
  "created_at": "2026-01-02T03:04:05Z",
  "release": {
    "component": "platform",
    "version": "1.4.2",
    "channel": "stable",
    "min_upgrade_from": "1.3.0",
    "security": false
  },
  "files": [
    { "path": "sp-platform_1.4.2.tar.gz",
      "sha256": "<lower-case hex>", "size": 73400320 }
  ]
}
```

* `v` is the format version (`1`); verifiers must reject other versions.
* `kind` is the fixed marker `sp-offline-bundle`.
* `release` mirrors the catalogue row: `min_upgrade_from` is the oldest
  appliance version that may apply the bundle (empty = no floor);
  `security` marks a security fix.
* `files[].sha256` covers the raw payload member bytes; `size` is the
  byte count. Both are verified during unpack — a tar member that does
  not match its manifest entry fails verification.

## SIGNATURE

UTF-8 JSON object — the same rotation-slot shape as the licence
document's `signatures` array:

```json
{ "signatures": [
    { "kid": "bundle-issuer-1", "alg": "Ed25519",
      "sig": "<base64 64-byte signature>" } ] }
```

`sig` is Ed25519 over the **raw MANIFEST member bytes** (no
re-canonicalisation — the bytes in the tar are the signed message). A
bundle verifies when **any** listed signature verifies against a
kid→public-key trust anchor the verifier holds — that is the key
rotation slot.

## Verification procedure

1. Gunzip + untar; collect `MANIFEST`, `SIGNATURE` and `payload/*`.
   Anything else is ignored but absence of MANIFEST or SIGNATURE is an
   error (`bundles: not an offline bundle`).
2. For each signature entry: look up `kid` in the verifier's trust set,
   require `alg` = `Ed25519`, verify `sig` over the MANIFEST bytes.
   Accept the bundle when one verifies; else fail
   (`bundles: no signature verified`).
3. Parse MANIFEST; require `v` = 1 and `kind` = `sp-offline-bundle`.
4. For every `files[]` entry, locate `payload/<path>` and check
   `sha256`/`size`. Missing or mismatched members fail.

## Key management

Bundles are signed by `bundle_signing_key_file` under
`bundle_signing_kid` (base64 Ed25519 key/seed, same file format as
`licence_signing_key_file`). When unset the generator signs with the
licence issuer key — a documented dev default; production should use a
distinct key so bundle signing rotates independently. Trust anchors are
distributed to appliances out of band (as `verification_keys` in
activation/offline-activation responses, or baked into the image).

## Staff API

`POST /v1/admin/releases/{id}/offline-bundle` (platform-admin session)
packs the release's stored artifact into
`storage/offline-bundles/serverperch-<component>-<version>.spb` and
answers `201` `{bundle, sha256, size_bytes, kid, verification_keys}`.
`GET /v1/admin/offline-bundles` lists the generated files.
