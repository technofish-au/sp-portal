# Release pipeline — CI upload + rsync targets (deploy stub, R5-4)

How release artifacts reach the portal's storage layout and catalogue.
This is the deploy leg's stub: the concrete TeamCity/Argo configuration
lands with the environment it deploys to, but the upload/rsync contract
is fixed here.

## Storage layout

Everything lives under `storage_dir` (default `/var/lib/sp-portal`):

```
releases/          catalogue artifacts — <component>/<version>/<file>
apt/               hosted apt repo — dists/<dist>/<comp>/binary-<arch>/, pool/
offline-bundles/   generated .spb bundles (docs/offline-bundles.md)
support-bundles/   appliance diagnostic uploads
exports/           generated data exports
```

## Registering a release from CI (TeamCity)

Build produces `<name>.tar.gz` for component `platform`, version `1.4.2`.
Two legs; pick per environment:

### Leg A — API upload (portal reachable from CI)

`POST /v1/admin/releases` with a **platform-admin session cookie**
(create a staff user; session = `POST /v1/auth/login` + TOTP). Upload
the artifact inline:

```sh
curl -fsS -b session.cookies \
  -F version=1.4.2 -F component=platform -F channel=stable \
  -F notes="$(cat CHANGELOG.md)" -F min_upgrade_from=1.3.0 \
  -F "artifact=@dist/sp-platform-1.4.2.tar.gz" \
  https://portal.example.com/v1/admin/releases
```

Then publish: `curl -b session.cookies -XPOST …/v1/admin/releases/<id>/publish`.

### Leg B — rsync + JSON register (CI rsyncs into storage, then registers)

```sh
# rsync the artifact into the catalogue layout on the portal host:
rsync -a dist/sp-platform-1.4.2.tar.gz \
  portal@portal-host:/var/lib/sp-portal/releases/platform/1.4.2/

# register the staged file (sha256 is verified server-side):
curl -fsS -b session.cookies -H 'content-type: application/json' \
  -d '{"version":"1.4.2","component":"platform","channel":"stable",
       "artifact_path":"platform/1.4.2/sp-platform-1.4.2.tar.gz"}' \
  https://portal.example.com/v1/admin/releases
```

## Apt repository rsync target

The appliance apt repo (`GET /apt/*`, docs/fakeportal.md) is plain files
under `storage_dir/apt/`. CI (reprepro/aptly on the build side) rsyncs
the generated repository:

```sh
rsync -az --delete repo/ \
  portal@portal-host:/var/lib/sp-portal/apt/
# repo layout: dists/stable/main/binary-amd64/{Release,Packages{,.gz}}
#              pool/main/sp-platform_1.4.2_amd64.deb …
```

Payload gating maps `pool/main/sp-platform_1.4.2_amd64.deb` → version
`1.4.2` → the catalogue row's `published_at`, so **register the release
before** rsyncing the pool files (unknown versions fall back to file
mtime — still gated, just coarser).

## Offline bundles

Bundles are generated on demand (`POST /v1/admin/releases/{id}/
offline-bundle`) into `offline-bundles/`; CI only needs to download the
.spb for distribution if it ships media.

## TeamCity configuration stub

Suggested build configuration parameters (fill in per environment):

| param                              | example                                     |
|------------------------------------|---------------------------------------------|
| `env.PORTAL_URL`                   | `https://portal.example.com`                |
| `env.PORTAL_STAFF_COOKIE_FILE`     | `secure:…` — session cookie jar             |
| `env.PORTAL_STORAGE_RSYNC_TARGET`  | `portal@portal-host:/var/lib/sp-portal`     |
| `env.RELEASE_CHANNEL`              | `stable`                                    |

Steps: `build` → `test` → `rsync or API upload` → `register` →
`publish` → (apt leg) `reprepro` → `rsync apt/`.
