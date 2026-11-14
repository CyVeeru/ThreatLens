# ThreatLens Data Layout

The runtime database and client artifacts live under `data/`, but only the
sanitized public exports are intended for GitHub.

| Path | Git status | Contents |
|---|---|---|
| `data.db` | ignored | Runtime SQLite workspace database (default path; override with `THREATLENS_DB_PATH`). May contain tenant/client data. |
| `../data.db` | ignored | Legacy root-level location. Still used automatically if it already exists. |
| `public/threatlens-threat-intel-public.db` | tracked | Sanitized public OSINT source catalog and threat-intel findings. |
| `public/threatlens-threat-actors-public.db` | tracked | Sanitized public threat actor profiles and appendices. |
| `portraits/` | ignored | Generated or uploaded TAP portraits. |
| `public/portraits/` | tracked when present | Watermarked curated TAP portraits prepared for public release. |
| `.threatlens-kek` | ignored | Local encryption key material. Never commit. |

## Refresh Public Exports

Run:

```bash
npm run db:export-public
```

The exporter reads the root `data.db` if it exists, otherwise `data/data.db`. You can also pass an explicit source:

```bash
node scripts/export-public-dbs.cjs data/data.db
```

To restore the public demo dataset into a local runtime workspace on a fresh
clone:

```bash
npm run db:restore-public
```

That command creates the git-ignored `data/data.db` (or `THREATLENS_DB_PATH`), imports the sanitized
public OSINT/TAP exports, and copies watermarked portraits from
`data/public/portraits/` into `data/portraits/` so Threat Actors cards render
locally. It refuses to overwrite an existing runtime DB unless called with
`npm run db:restore-public -- --force`.

## Public Export Privacy Rules

The public threat-intel export removes tenant ids, draft emails, analyst tags,
triage status, full source article bodies, provider errors, retry state, and
client relevance fields.

The public threat-actor export removes tenant ids, tenant relevance tagging,
detection-rule links, author identity, client-specific relevance ratings, and
portrait file paths.

The private workspace export is for local backup and inspection only. It is
ignored by Git and should not be uploaded to GitHub.
