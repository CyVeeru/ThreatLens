# Verifying ThreatLens Releases

This file explains how to verify release artifacts before running them locally.

## Signing Key

Release artifacts are signed with the maintainer's release key once it is
published. The public key will live at:

```text
signing/keys/tejacyberx-public.asc
```

together with its fingerprint, recorded in this file. Until the key is
published, releases are unsigned: verify them with the checksum manifest below
and by downloading only from the project's GitHub Releases page.

The release workflow signs artifacts only when the repository secrets
`THREATLENS_RELEASE_GPG_PRIVATE_KEY` and `THREATLENS_RELEASE_GPG_PASSPHRASE` are
configured, and skips signing otherwise.

## Import The Public Key

Once the key is published, from the repository root:

```bash
gpg --import signing/keys/tejacyberx-public.asc
gpg --fingerprint
```

Confirm the displayed fingerprint exactly matches the one recorded in this file
and on the maintainer's GitHub profile.

## Verify A Source Archive

For a release archive such as:

```text
threatlens-batchone-vX.Y.Z.tar.gz
threatlens-batchone-vX.Y.Z.tar.gz.asc
SHA256SUMS
SHA256SUMS.asc
```

Verify the checksum manifest:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS   # signed releases only
sha256sum -c SHA256SUMS
```

Then verify the archive signature:

```bash
gpg --verify threatlens-batchone-vX.Y.Z.tar.gz.asc threatlens-batchone-vX.Y.Z.tar.gz
```

On macOS, use `shasum -a 256 -c SHA256SUMS` if `sha256sum` is not installed.

## Verify A Git Tag

If the release is published as a signed Git tag:

```bash
git fetch --tags
git tag -v vX.Y.Z
```

The tag signer should match the release key fingerprint recorded in this file.

## Verify The Public Seed Data

ThreatLens ships sanitized public seed data under:

```text
data/public/threatlens-threat-intel-public.db
data/public/threatlens-threat-actors-public.db
data/public/portraits/
```

These files are public release assets. They contain public threat intelligence
(including real indicators of compromise, file paths and domains taken from
published advisories) but no API keys, credentials or private runtime state.
Local runtime state is restored with:

```bash
npm run db:restore-public
```

This creates local git-ignored runtime files such as `data.db` and `data/portraits/`.

## Security Notes

- Do not trust unsigned archives from anywhere other than the project's GitHub
  Releases page, altered checksums, or signed assets whose fingerprint does not
  match this file.
- ThreatLens ships no passwords. Each install generates its own first-run
  credentials; change them at first sign-in and enrol MFA before using
  ThreatLens with real data.
- AI provider keys are never bundled in public seed data. Configure them locally
  in AI Settings after verification.
- Report suspected signing-key compromise or release tampering using the
  process in `SECURITY.md`.
