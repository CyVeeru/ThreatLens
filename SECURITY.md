# Security

## Public default credentials: rotate immediately

The seeded local credentials are public knowledge because they are documented
in this repository and may also appear in local seed data. They are intended only
to get a fresh local instance through first login. A stale default administrator
account is a high-risk deployment finding.

On first boot, ThreatLens forces seeded accounts through temporary-password
change before platform functions unlock. TOTP MFA is available and opt-in; set
`THREATLENS_REQUIRE_MFA=1` to force enrolment for every account, which is
recommended for any shared or internet-reachable deployment. Before using real
data, create named operator accounts, enroll MFA, then rotate,
disable, or delete the seed accounts from Platform Users.

## What to rotate immediately after first boot

| Item | Where | How to rotate |
|---|---|---|
| **First-run accounts** `admin@threatlens.local`, `reviewer@threatlens.local` | Created by `ensurePlatformSeedUsers()` in `server/storage.ts` with a password generated per install (~124 bits); the plaintext is parked in `data/initial-credentials.json` (mode 600, git-ignored). | A password change is forced on first login, which prunes the account from `data/initial-credentials.json` and deletes the file once empty. Create named accounts, then delete the first-run accounts in Platform Users. MFA enrolment is offered and can be enforced with `THREATLENS_REQUIRE_MFA=1`. |
| **Bearer sessions** | `auth_sessions.token_hash` (opaque token issued by `/api/v1/auth/login`). | Logout revokes the current session. Rotating all sessions means deleting rows from `auth_sessions`. |
| **AI provider keys** | `data/secrets/threatlens-secrets.db` per tenant/provider. | `/#/ai-settings` → edit each row. Metadata and masks remain in `ai_providers`; encrypted ciphertext is stored separately and encrypted with the per-instance key in `data/.threatlens-kek`. |

## Threat model

ThreatLens Batch One release is an MSSP **back-office** tool. It is assumed to run behind:

* A reverse proxy that terminates TLS (Cloudflare Tunnel, nginx, Caddy).
* An authentication boundary (the dashboard's own login is a baseline; a corporate SSO/SAML layer in front is recommended for production deployments).
* A private network — port 7099 must **never** be exposed directly to the public internet.

The internal authn model is intentionally simple but production-hardened enough for a private back-office deployment:

1. **Passwords are hashed on login** — legacy plaintext seeded rows are transparently rehashed to `scrypt:v1` after the first successful login. New password-management UI should write the same format.
2. **Add SSO / OIDC** — wire `passport-openidconnect` into the existing Passport middleware in `routes.ts`.
3. **Rate limiting is built in for sensitive public edges** — `/api/v1/auth/login` uses in-memory throttling. Put Cloudflare/nginx limits in front for distributed production traffic.

## What is encrypted, what is not

| Class of data | Storage | Encrypted? |
|---|---|---|
| User passwords | `users.password` | `scrypt:v1` hashes after first successful legacy login. |
| Session tokens | `auth_sessions.token_hash` | SHA-256 hash of an opaque random bearer token; raw token is only returned once. |
| AI provider keys | `data/secrets/threatlens-secrets.db` | AES-256-GCM ciphertext with per-instance key at `data/.threatlens-kek`; keep this DB outside public data exports and keep disk-level encryption enabled. |
| Connector API keys/secrets | `data/secrets/threatlens-secrets.db` | Same secret store as AI provider keys; only masks remain in the workspace DB. |
| Finding content (OSINT) | `osint_findings.*` | Public-source data — not sensitive. |
| Portrait images | `data/portraits/*` | Filesystem only. Validated by magic-byte sniff on upload (`POST /api/v1/threat-actors/:aid/portrait/upload`). |

## Upload validation

`POST /api/v1/threat-actors/:aid/portrait/upload` accepts only:

* PNG / JPEG / WebP / GIF (extension regex AND magic-byte sniff).
* Maximum 5 MB.

Add any future uploads through the same JSON+base64 pattern. There is no multer / multipart endpoint by design, and a 50 MB body limit applies globally in `server/index.ts`.

## CORS

The Express server does not set CORS headers by default — the client is served from the same origin. If you split the deployment (separate API host), add `cors` middleware in `server/index.ts` with an explicit allowlist.

## Logging

* Every `/api/*` request is logged with method, path, status, duration, and a redacted response preview.
* Errors are logged via `console.error("Internal Server Error:", err)`.
* API keys, tokens, passwords, large result bodies, report content, uploaded file content, and AI outputs are redacted/truncated in the request log middleware.

## Secret Store Boundary

ThreatLens separates credentials from exportable workspace data. OSINT findings, TAP dossiers, and public release databases can live in the main workspace SQLite files; API-provider and connector credential ciphertext belongs in `data/secrets/threatlens-secrets.db` or the path configured by `THREATLENS_SECRET_DB`.

On boot, legacy ciphertext found in `ai_providers.api_key_enc`, `integrations.api_key_enc`, or `integrations.api_secret_enc` is migrated into the secret DB and removed from the public workspace DB columns. Keep this migration enabled as a release security control.

## Reporting vulnerabilities

Please report suspected vulnerabilities privately through GitHub Private
Vulnerability Reporting when it is enabled for the repository, or by contacting
the project maintainer listed in the repository metadata. Do not file public
issues for vulnerabilities until a maintainer has confirmed disclosure timing.

Do not include client data, live credentials, API keys, private logs, or exploit
payloads beyond the minimum needed to reproduce the issue. A good report
includes affected version or commit, impact, reproduction steps, and suggested
remediation if known.
