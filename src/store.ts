/**
 * Change tracking: a sealed remote manifest plus a local base state.
 *
 * Diff rules per key (sha256 of plaintext drives change detection,
 * mtime only breaks ties on first contact):
 * - local only            -> push
 * - remote only           -> pull
 * - same sha              -> up to date
 * - local == base         -> remote changed -> pull
 * - remote == base        -> local changed -> push
 * - no base (never synced)-> last-writer-wins by mtime (ties push)
 * - otherwise             -> conflict (both sides diverged; keep both,
 *                            never silently drop either side)
 *
 * The base lives in <agentDir>/.omp-sync/state.json and is refreshed to
 * the agreed view after every successful push/pull.
 */
import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  createReadStream,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { openBounded, seal } from "./crypto.js";
import { EtagMismatchError, type ObjectStore } from "./s3.js";
import { manifestObjectKey, readSessionHeader } from "./keys.js";

export interface ManifestEntry {
  /** Stable logical id, e.g. sessions/home/dev/bengu/<file>.jsonl. Diff and base match on this. */
  id: string;
  /** Immutable content-addressed object key holding exactly these bytes. */
  key: string;
  /** sha256 of the PLAINTEXT session file. */
  sha256: string;
  /** Plaintext size in bytes. */
  size: number;
  /** File mtime in ms epoch. */
  mtime: number;
  /** Verbatim header cwd (drives pull targeting). Null when unreadable. */
  cwd: string | null;
  /** Canonical project key (redundant, handy for status display). */
  canonical: string;
}

export interface Manifest {
  version: 1;
  updatedAt: number;
  entries: ManifestEntry[];
}

export interface LocalFile {
  absPath: string;
  filename: string;
  sha256: string;
  size: number;
  mtime: number;
  headerCwd: string | null;
  /** Stable logical id (see ManifestEntry.id). */
  id: string;
  canonical: string;
}

function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    const s = createReadStream(path);
    s.on("data", (c) => h.update(c as Buffer));
    s.on("error", reject);
    s.on("end", () => resolve(h.digest("hex")));
  });
}

/**
 * Scan <sessionsRoot> one level deep for *.jsonl session files.
 * Directories (including omp's per-session sidecar dirs) and non-jsonl
 * files are ignored. Never throws on a missing root — returns [].
 */
export async function scanLocalSessions(
  sessionsRoot: string,
  idFor: (filename: string, headerCwd: string | null) => { id: string; canonical: string },
): Promise<LocalFile[]> {
  let dirs: string[];
  try {
    dirs = readdirSync(sessionsRoot, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name);
  } catch {
    return [];
  }
  const out: LocalFile[] = [];
  for (const dir of dirs) {
    const dirPath = join(sessionsRoot, dir);
    let files: string[];
    try {
      files = readdirSync(dirPath);
    } catch {
      continue;
    }
    for (const f of files) {
      if (!f.endsWith(".jsonl")) continue;
      const abs = join(dirPath, f);
      let st: { size: number; mtimeMs: number; isFile: () => boolean };
      try {
        st = statSync(abs);
        if (!st.isFile()) continue;
      } catch {
        continue; // vanished mid-scan
      }
      let sha: string;
      try {
        sha = await sha256File(abs);
      } catch {
        continue; // vanished or unreadable mid-scan
      }
      const { cwd } = readSessionHeader(abs);
      const { id, canonical } = idFor(f, cwd);
      out.push({ absPath: abs, filename: f, sha256: sha, size: st.size, mtime: st.mtimeMs, headerCwd: cwd, id, canonical });
    }
  }
  return out;
}

export interface Diff {
  toPush: LocalFile[];
  toPull: ManifestEntry[];
  conflicts: { local: LocalFile; remote: ManifestEntry }[];
  upToDate: number;
}

export function diffWithBase(local: LocalFile[], remote: Manifest | null, base: Record<string, string>): Diff {
  const r = new Map((remote?.entries ?? []).map((e) => [e.id, e]));
  const l = new Map(local.map((e) => [e.id, e]));
  const out: Diff = { toPush: [], toPull: [], conflicts: [], upToDate: 0 };

  for (const e of local) {
    const rem = r.get(e.id);
    if (!rem) {
      out.toPush.push(e); // new locally
      continue;
    }
    if (rem.sha256 === e.sha256) {
      out.upToDate++;
      continue;
    }
    const b = base[e.id];
    if (b === undefined) {
      // First contact: last-writer-wins by mtime, ties push.
      if (e.mtime >= rem.mtime) out.toPush.push(e);
      else out.toPull.push(rem);
    } else if (b === e.sha256) {
      out.toPull.push(rem); // local untouched, remote moved
    } else if (b === rem.sha256) {
      out.toPush.push(e); // remote untouched, local moved
    } else {
      out.conflicts.push({ local: e, remote: rem }); // both diverged
    }
  }
  if (remote) {
    for (const e of remote.entries) {
      // Remote-only: local deleted it, or a fresh machine. Remote wins = fetch.
      // Deletions never propagate via push, so this is strictly additive.
      if (!l.has(e.id)) out.toPull.push(e);
    }
  }
  return out;
}

// --- local base state --------------------------------------------------------

const STATE_DIRNAME = ".omp-sync";

export function stateDir(agentDir: string): string {
  return join(agentDir, STATE_DIRNAME);
}

export interface LocalState {
  version: 2;
  /** logical id -> sha256 both sides agreed on at the last successful sync. */
  lastSynced: Record<string, string>;
}

const KEYS_DIRNAME = "keys";

function keysDir(agentDir: string): string {
  return join(stateDir(agentDir), KEYS_DIRNAME);
}

function keyRecordPath(agentDir: string, id: string): string {
  // Filename is a hash (ids contain slashes); content carries the id back.
  const h = createHash("sha256").update(id, "utf-8").digest("hex");
  return join(keysDir(agentDir), `${h}.json`);
}

export function loadLocalState(agentDir: string): LocalState {
  const lastSynced: Record<string, string> = {};
  // One-time migration: a v2 snapshot's entries move to per-key files so
  // later writers never need read-modify-write. Idempotent and safe under
  // concurrency (same content, atomic renames, stale snapshot unlinked).
  try {
    const raw = JSON.parse(readFileSync(join(stateDir(agentDir), "state.json"), "utf-8")) as Partial<LocalState>;
    if (raw && typeof raw === "object" && raw.version === 2 && raw.lastSynced && typeof raw.lastSynced === "object") {
      mkdirSync(keysDir(agentDir), { recursive: true });
      for (const [id, sha256] of Object.entries(raw.lastSynced)) {
        if (typeof id === "string" && typeof sha256 === "string") {
          try {
            writeFileAtomic(keyRecordPath(agentDir, id), Buffer.from(JSON.stringify({ id, sha256 })));
          } catch {
            /* a concurrent migrator won; per-key reads below still converge */
          }
        }
      }
      try {
        rmSync(join(stateDir(agentDir), "state.json"), { force: true });
      } catch {
        /* already unlinked by a concurrent migrator */
      }
    }
  } catch {
    /* missing, corrupt, or legacy -> per-key files below decide */
  }
  let names: string[];
  try {
    names = readdirSync(keysDir(agentDir));
  } catch {
    return { version: 2, lastSynced };
  }
  for (const name of names) {
    if (!/^[0-9a-f]{64}\.json$/.test(name)) continue;
    try {
      const rec = JSON.parse(readFileSync(join(keysDir(agentDir), name), "utf-8")) as { id?: unknown; sha256?: unknown };
      if (rec && typeof rec.id === "string" && typeof rec.sha256 === "string") lastSynced[rec.id] = rec.sha256;
    } catch {
      /* torn write from a killed process; the key simply re-syncs */
    }
  }
  return { version: 2, lastSynced };
}

/**
 * Record exactly the logical ids this operation synced successfully —
 * nothing more. Each id lands in its own atomic file with no read step,
 * so concurrent processes recording disjoint ids can never lose each
 * other's updates (no read-modify-write cycle at all).
 */
export function markSynced(agentDir: string, ids: { id: string; sha256: string }[]): void {
  if (!ids.length) return;
  mkdirSync(keysDir(agentDir), { recursive: true });
  for (const e of ids) {
    writeFileAtomic(keyRecordPath(agentDir, e.id), Buffer.from(JSON.stringify({ id: e.id, sha256: e.sha256 })));
  }
}

/** Atomic file replace: crash mid-write leaves the old file, never a half one. */
export function writeFileAtomic(dest: string, data: Buffer): void {
  const tmp = `${dest}.tmp-${process.pid}-${randomUUID()}`;
  writeFileSync(tmp, data);
  renameSync(tmp, dest);
}

// --- remote manifest ---------------------------------------------------------

const enc = (s: string): Buffer => Buffer.from(s, "utf-8");

/** Hard cap on manifest plaintext (zip-bomb defense; manifests are kilobytes). */
export const MANIFEST_MAX_BYTES = 64 * 1024 * 1024;

/**
 * GET + decrypt the manifest. Null when absent (nothing pushed yet).
 * The ETag comes from the same GET response as the bytes, so a concurrent
 * writer can never pair a HEAD generation with a GET generation.
 */
export async function loadRemoteManifest(
  s3: ObjectStore,
  prefix: string,
  key: Buffer,
): Promise<{ manifest: Manifest; etag?: string } | null> {
  const objectKey = manifestObjectKey(prefix);
  const got = await s3.getObject(objectKey);
  if (!got) return null;
  // AAD binds the manifest to its object key: a manifest copied from another
  // prefix under the same encryption key is rejected instead of redirecting
  // pulls into the wrong namespace.
  const manifest = JSON.parse(
    (await openBounded({ body: got.body }, key, MANIFEST_MAX_BYTES, enc(objectKey))).toString("utf-8"),
  ) as Manifest;
  if (!manifest || manifest.version !== 1 || !Array.isArray(manifest.entries)) {
    throw new Error("remote manifest has an unknown shape");
  }
  return { manifest, etag: got.etag };
}

/**
 * Encrypt + PUT the manifest with optimistic concurrency. First creation is
 * conditional too (If-None-Match), so two simultaneous first-pushes merge
 * instead of one silently clobbering the other.
 *
 * On 412 the merge overlays ONLY `overlayKeys` (keys this writer uploaded)
 * onto the winner's manifest. Overlaying our whole stale manifest would
 * restore old hashes for disjoint keys a concurrent writer just updated.
 * Omit overlayKeys only when the manifest is built fresh (tests/seeds).
 */
export async function saveRemoteManifest(
  s3: ObjectStore,
  prefix: string,
  manifest: Manifest,
  key: Buffer,
  expectedEtag?: string,
  retries = 3,
  overlayKeys?: Set<string>,
): Promise<void> {
  const objectKey = manifestObjectKey(prefix);
  const body = seal(enc(JSON.stringify(manifest)), key, enc(objectKey)).body;
  try {
    if (expectedEtag === undefined) {
      await s3.putObject(objectKey, body, "application/octet-stream", { ifNoneMatch: true });
    } else {
      await s3.putObject(objectKey, body, "application/octet-stream", { ifMatch: expectedEtag });
    }
    return;
  } catch (e) {
    if (!(e instanceof EtagMismatchError) || retries <= 0) throw e;
  }
  // Lost the race: rebase our owned ids onto the winner and retry.
  const current = await loadRemoteManifest(s3, prefix, key);
  const byKey = new Map((current?.manifest.entries ?? []).map((en) => [en.id, en]));
  for (const en of manifest.entries) {
    if (!overlayKeys || overlayKeys.has(en.id)) byKey.set(en.id, en);
  }
  const merged: Manifest = { version: 1, updatedAt: Date.now(), entries: [...byKey.values()] };
  await saveRemoteManifest(s3, prefix, merged, key, current?.etag, retries - 1, overlayKeys);
}

// --- process lock ------------------------------------------------------------

export const LOCK_STALE_MS = 30 * 60 * 1000;

interface LockFile {
  id: string;
  pid: number;
  command: string;
  startedAt: string;
}

export function lockPath(agentDir: string): string {
  return join(stateDir(agentDir), "lock");
}

/** A lock we cannot read or parse counts as stale (a crashed writer's half-line must not wedge us). */
export function isStaleLock(lock: LockFile | undefined, now = Date.now()): boolean {
  if (!lock || typeof lock !== "object") return true;
  if (!Number.isInteger(lock.pid) || lock.pid <= 0) return true;
  try {
    process.kill(lock.pid, 0);
    return false; // someone alive holds that pid
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return true;
    if (code === "EPERM") return now - Date.parse(lock.startedAt) > LOCK_STALE_MS;
    return true;
  }
}

export function readLock(agentDir: string): LockFile | undefined {
  try {
    return JSON.parse(readFileSync(lockPath(agentDir), "utf-8")) as LockFile;
  } catch {
    return undefined;
  }
}

export class LockHeldError extends Error {
  readonly stale: boolean;
  constructor(message: string, stale: boolean) {
    super(message);
    this.name = "LockHeldError";
    this.stale = stale;
  }
}

/** Exclusive-create lock; throws LockHeldError when held or stale. */
export async function withLock<T>(agentDir: string, command: string, fn: () => Promise<T>): Promise<T> {
  mkdirSync(stateDir(agentDir), { recursive: true });
  const lock: LockFile = { id: randomUUID(), pid: process.pid, command, startedAt: new Date().toISOString() };
  const path = lockPath(agentDir);
  let created = false;
  try {
    const fd = openSync(path, "wx"); // EEXIST when held
    writeSync(fd, JSON.stringify(lock));
    closeSync(fd);
    created = true;
    return await fn();
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      const cur = readLock(agentDir);
      if (isStaleLock(cur)) {
        throw new LockHeldError(
          `omp-sync lock is stale${cur && Number.isInteger(cur.pid) ? ` (pid ${cur.pid})` : ""}. Run omp-sync unlock --stale, then retry.`,
          true,
        );
      }
      throw new LockHeldError(
        `omp-sync already running${cur ? ` (${cur.command}, pid ${cur.pid})` : ""}.`,
        false,
      );
    }
    throw e;
  } finally {
    if (created) {
      const cur = readLock(agentDir);
      if (cur?.id === lock.id) {
        try {
          rmSync(path, { force: true });
        } catch {
          /* best effort */
        }
      }
    }
  }
}

