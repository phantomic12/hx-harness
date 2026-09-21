# Code signing (Sigstore keyless)

`hx` release artifacts are signed with **keyless** Sigstore code signing. "Keyless"
means there is no private key to store, rotate, or leak: the signature is bound to the
GitHub Actions OIDC identity of the `release.yml` workflow run that built the artifacts.
Anyone can verify the signature with the standard [`cosign`](https://docs.sigstore.dev/cosign/installation)
tool against Sigstore's public transparency log — no trust in GitHub's attestation store is
required.

## What is signed

The release workflow signs **every** artifact in `dist/`, one detached `.sig` blob per file:

- `hx-<version>-<target>.tar.gz` / `.zip` for each of the five targets
- `SHA256SUMS` → `SHA256SUMS.sig`

`SHA256SUMS.sig` is the one `install.sh` verifies, because it in turn pins every
archive's checksum. A signature over `SHA256SUMS` therefore transitively vouches for all
five binaries.

## Verify a release archive with cosign

```sh
# Download the release for your platform
curl -fsSL -O https://github.com/phantomic12/hx-harness/releases/download/v1.2.3/SHA256SUMS
curl -fsSL -O https://github.com/phantomic12/hx-harness/releases/download/v1.2.3/SHA256SUMS.sig

# Verify the signature (this is exactly what install.sh runs when cosign is present)
cosign verify-blob \
  --signature SHA256SUMS.sig \
  --cert-identity-regexp 'https://github.com/phantomic12/hx-harness/.github/workflows/release.yml@refs/tags/v.*' \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

A successful run prints `Verified OK`. Then confirm the archive's checksum against
`SHA256SUMS` as normal:

```sh
sha256sum -c SHA256SUMS  # or the matching line for your archive
```

## Expected certificate identity and OIDC issuer

The signing certificate carries two fields cosign checks:

| Field | Value |
|---|---|
| Certificate identity (SAN) | `https://github.com/<owner>/<repo>/.github/workflows/release.yml@refs/tags/v*` |
| OIDC issuer | `https://token.actions.githubusercontent.com` |

The pattern `@refs/tags/v*` is **not** an exact match: `--cert-identity-regexp`
is a regex, so the `.*` at the end matches the concrete tag. A signature is only valid
if it was produced by this repository's `release.yml` running on a `v*` tag, issued by
GitHub Actions. An attacker who could not run that workflow could not mint a valid signature.

## Install the installer

`install.sh` verifies the signature automatically when `cosign` is on your `PATH`:

- ✅ `cosign` present → downloads `SHA256SUMS.sig` and verifies it before unpacking.
- ❌ `cosign` missing → falls back to **checksum-only** verification (the default for most
  users) with a warning that the additional layer is available and how to install it.
- `COSIGN_SKIP=1` → skips signature verification entirely and says so.

Signature verification never blocks a checksum-correct install for a user without cosign — it is
an extra layer, not a new requirement.
