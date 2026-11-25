# git-compass-releases

The signed module registry of Git Compass, plus `gcpack`, the tool that
packs, signs and publishes module packages. Git Compass (git-compass-core)
reads this repository to list, install, update, roll back and disable modules.

## What is published

```
catalog.json                       signed list of published modules
modules/<id>/index.json            signed per-module index: versions, files, revocations, minVersion
GitHub release <id>-v<version>     the package archives (one zip per OS/arch)
app/index.json                     signed index of the Git Compass app itself (in-app updater feed)
GitHub release app-v<version>      the app installers (dmg/zip, NSIS exe, AppImage/deb/rpm)
keys/registry.pub                  public key(s) the documents are signed with
```

Each signed document is `{"signed": {...}, "signatures": [{"keyid", "sig"}]}`;
the ed25519 signature covers the exact bytes of `signed` (domain-separated).
An index lists, for every version, each archive's URL, SHA-256 and size, so
the signature covers every byte a client installs. Indexes and the catalog
carry an increasing `sequence` (clients refuse an older one: no replay of a
pre-revocation index) and an `expires` date 120 days out (the monthly
`resign` workflow refreshes it).

## How core uses it

- Settings → Modules → *Available modules* lists `catalog.json`. Install,
  update, switching to another version and rollback download the archive,
  check size + SHA-256 against the signed index, unpack into
  `<UserConfigDir>/git-compass/modules/<id>/<version>/` and keep only the
  active and the previous version.
- A switched-on module is started right after an update; if it does not
  start, core rolls back to the previous version automatically.
- A revoked version, or one below `minVersion`, is **disabled**: its process
  is stopped, calls are refused, and the app shows a banner offering the update.
- Offline, core uses the last verified copy of each document (kept under
  `<config>/registry/`), so revocations stay in force.
- The public key is embedded in core (`internal/installer/keys.go`).
  `GIT_COMPASS_REGISTRY_URL` / `GIT_COMPASS_REGISTRY_KEYS` point a dev build
  at a local registry.

## Publishing (GitHub Actions)

| Workflow | Does |
| --- | --- |
| `publish` | inputs `repo` (e.g. `git-compass-docker`), `ref`, notes. Tests and builds the module (`ALL=1 scripts/package.sh` → `dist/pkg`), packs per platform, signs, creates release `<id>-v<version>` with the zips, commits the index + catalog. Versions are immutable. |
| `manage` | `revoke` / `unrevoke` a version (with a reason shown to users) or set `min-version`. |
| `resign` | monthly (and manual): new sequence + expiry on every document. |
| `publish-app` | inputs `version`, `ref` (of git-compass-core), notes. Builds the app on macOS (universal .app → zip + dmg), Windows (per-user NSIS installer) and Linux (AppImage, deb, rpm), creates release `app-v<version>`, signs `app/index.json`. Update payloads: macOS zip, Windows installer, Linux AppImage. Needs GitHub-hosted macOS and Windows runners. |
| `ci` | `go test`, and `gcpack verify` of the committed documents. |

Module repo contract: `manifest.json` (version = the version to publish) and
`scripts/package.sh` that builds every platform in the manifest when `ALL=1`.

## Secrets and settings

- `GC_SIGNING_KEY` (Actions secret of this repo): the private key, `gcsk1:…`.
  Make it once on your own machine:

  ```
  go run github.com/git-compass-dev/git-compass-releases/cmd/gcpack@main keygen -out registry.key
  ```

  It prints the public key (`gcpk1:…`). Put the file's content in the secret,
  the public key in `keys/registry.pub` and in core's `OfficialKeys`, then
  keep `registry.key` offline (password manager). Never commit it.
- `GC_READ_TOKEN` (already set): reads the private module repos while building.
- Optional OS code signing for `publish-app` (without them builds are unsigned:
  macOS needs right click → Open on first launch, Windows SmartScreen warns):
  - macOS: `APPLE_CERT_P12` (base64 Developer ID Application .p12),
    `APPLE_CERT_PASSWORD`, `APPLE_SIGN_IDENTITY`; notarization also needs
    `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD` (app-specific password).
  - Windows: `WINDOWS_CERT_PFX` (base64 .pfx), `WINDOWS_CERT_PASSWORD`.
- The repository must be **public** so the app can download archives and
  documents without a token.

Key rotation: add the new public key to core's `OfficialKeys` and ship it,
then switch `GC_SIGNING_KEY` and run `resign`; drop the old key in a later release.

## gcpack locally

```
gcpack keygen -out signing.key
gcpack pack -pkg dist/pkg -out dist/zip
GC_SIGNING_KEY=$(cat signing.key) gcpack publish -repo . -pkg dist/pkg -out dist/zip -download-base http://127.0.0.1:8099/dl/docker-v0.2.0
GC_SIGNING_KEY=$(cat signing.key) gcpack revoke -repo . -id docker -version 0.1.0 -reason "crash on start"
gcpack verify -repo . -pubkey gcpk1:...
```

The signing key is read only from `$GC_SIGNING_KEY`, never from a flag.
