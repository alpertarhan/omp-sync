# omp-sync — Encrypted Per-Session Sync for omp

[![npm](https://img.shields.io/npm/v/omp-sync)](https://www.npmjs.com/package/omp-sync)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

`omp-sync` syncs your [omp](https://github.com/can1357/oh-my-pi) coding-agent
sessions across machines through any S3-compatible storage (AWS S3,
Cloudflare R2, IDrive E2, MinIO, …).
Every session JSONL is stored as its own object, wrapped as
`AES-256-GCM(gzip(plaintext))` and bound to its object key. Objects are
content-addressed and immutable: a failed push can never corrupt the
previously published generation, and pulls cryptographically verify every
byte before it touches disk.

## Install

```bash
omp plugin install npm:omp-sync
```

## Quick start

1. Create a bucket on any S3-compatible storage and grab the endpoint,
   region, and access keys.

2. Write the config to `<agentDir>/omp-sync.local.json`
   (default agent dir: `~/.omp/agent`):

   ```json
   {
     "endpoint": "https://<bucket-host>",
     "bucket": "<bucket>",
     "region": "auto",
     "accessKeyId": "...",
     "secretAccessKey": "..."
   }
   ```

   Every field can also come from the environment
   (`OMP_SYNC_ENDPOINT`, `OMP_SYNC_BUCKET`, `OMP_SYNC_REGION`,
   `OMP_SYNC_ACCESS_KEY_ID`, `OMP_SYNC_SECRET_ACCESS_KEY`).

3. Generate the encryption key **once per machine set** — it is shared by
   all machines but never leaves them (it is not synced, ever):

   ```bash
   echo "export OMP_SYNC_ENCRYPTION_KEY=\"$(openssl rand -base64 32)\"" >> ~/.zshrc
   ```

4. In omp, run:

   ```text
   /omp-sync doctor
   ```

   …should report `config ok`, `encrypt key ok (32-byte)`, `bucket reachable`.
   Then on your first machine:

   ```text
   /omp-sync push
   ```

   On the second machine:

   ```text
   /omp-sync pull
   ```

## Commands

| Command              | What it does                                                       |
| -------------------- | ------------------------------------------------------------------ |
| `/omp-sync status`   | Local vs remote diff. Never writes sessions or remote objects (a one-time local base-state migration may run after upgrades). |
| `/omp-sync push`     | Upload new/changed local sessions (last-writer-wins on first contact). |
| `/omp-sync pull`     | Download remote sessions (never touches your open session file).   |
| `/omp-sync blobs`    | Full two-way reconcile of the attachment blob store.               |
| `/omp-sync doctor`   | Config + key + bucket + lock diagnostics. Works without a config.  |
| `/omp-sync config`   | Show resolved (secret-redacted) configuration.                     |
| `/omp-sync unlock`   | Inspect/remove a stale lock. Works without a config.               |

Automation (no commands needed day to day):

- **After each turn**, the current session file is pushed (debounced, one
  small upload — no shutdown race).
- **On startup**, an opt-in pull fetches other sessions (`autoPull`, off by
  default, never overwrites the open file).
- **On shutdown**, a best-effort final push of the current file runs inside
  omp's handler budget.

## Conflict handling

When both sides edited the same session since the last sync, nothing is
silently overwritten: the remote version is preserved next to your file as
`<session>.conflict-<timestamp>.jsonl`, your bytes stay untouched, and the
next push adopts your side. The copy syncs up like any other session, so
both versions survive on every machine.

## Configuration reference

`omp-sync.local.json` (or `OMP_SYNC_*` env vars):

| Key / env                        | Default      | Meaning                                              |
| -------------------------------- | ------------ | ---------------------------------------------------- |
| `endpoint` / `OMP_SYNC_ENDPOINT` | — (required) | Storage endpoint incl. scheme. If the endpoint's first host label equals the bucket name (e.g. bucket `s3` with `https://s3.example.com`), embed the bucket in the host instead to force virtual-hosted addressing |
| `region` / `OMP_SYNC_REGION`     | `auto`       | SigV4 region                                         |
| `accessKeyId/secretAccessKey`    | — (required) | Storage credentials                                  |
| `prefix` / `OMP_SYNC_PREFIX`     | `omp-sync/`  | Bucket namespace for all objects                     |
| `autoPush` / `OMP_SYNC_AUTO_PUSH` | `true`      | Debounced per-turn push of the current session       |
| `autoPull` / `OMP_SYNC_AUTO_PULL` | `false`     | Pull other sessions on startup                       |
| `debounceMs`                     | `5000`       | Turn-end push debounce                               |
| `includeBlobs` / `OMP_SYNC_BLOBS` | `true`      | Sync `blob:sha256:` attachments alongside sessions   |
| `maxBlobBytes`                   | `33554432`   | Oversized blobs are skipped with a warning on push; sessions referencing them fail to pull until the limit is raised |
| `pathMap` / `OMP_SYNC_PATHMAP`   | `[]`         | `[{from, to}]` prefix rewrites for differing home dirs |
| `OMP_SYNC_ENCRYPTION_KEY`        | — (required) | Base64 of 32 random bytes, shared across machines    |
| `OMP_SYNC_TIMEOUT_MS`            | `15000`      | Per-request network timeout                          |

## How it works

- **Keys** derive from the session header's `cwd`, never from the on-disk
  bucket directory (which is lossy). Two omp machines converge on the same
  keys for the same project, across macOS and Linux.
- **Change tracking** is sha256-of-plaintext plus a local agreed-base, with
  mtime tie-breaking only on first contact.
- **Manifest** (`<prefix>manifest.json`, itself sealed) is a truthful index
  of remote objects, updated with `If-Match` optimistic concurrency and
  bounded retries — concurrent pushes merge instead of clobbering.
- **Pulls** land in omp's own sessions tree (`<agentDir>/sessions/<omp
  bucket>/`, or `$XDG_DATA_HOME/omp/sessions/...` when omp is
  XDG-redirected). Project working directories are never written to.
- **Deletions never propagate**: the store is additive; deleting locally and
  pushing does not delete remotely.

## Security notes

- Payloads are `AES-256-GCM(gzip(plaintext))` with a fresh 96-bit nonce per
  object; session, blob, and manifest envelopes are each bound (AAD) to
  their object key, so swapped or cross-prefix objects are rejected.
- The storage operator sees only opaque blobs, content hashes, sizes, and
  modification times — never prompts, code, or file contents (note: object
  keys do reveal the sanitized project directory layout and per-object
  sizes, which are listable).
- Downloads are hash-verified and size-bounded before they reach disk;
  oversized or mismatched objects are refused, never partially applied.
- Credentials live in `omp-sync.local.json` / env on each machine.
  The encryption key lives **only** in `OMP_SYNC_ENCRYPTION_KEY`.

## Requirements
- omp coding agent (developed and tested against omp `18.1.13`).
- Node 22+ or Bun (for the `fetch`, `AbortSignal.timeout`, and
  `Promise.withResolvers` runtimes used internally).

## License

MIT — see [LICENSE](./LICENSE).
