/**
 * Sync engine: push/pull/status/doctor over sealed per-session objects.
 *
 * Invariants (every one exists because violating it corrupts sync):
 * - Object keys derive from the session header `cwd`, never from the
 *   on-disk bucket directory name (lossy and flavor-specific).
 * - Pulls land under <sessionsRoot>/<omp bucket dir> — the only tree the
 *   host discovers sessions from. Never the project working directory.
 * - The remote manifest is a truthful index of REMOTE OBJECTS: untouched
 *   keys pass through verbatim; only successfully uploaded keys are
 *   replaced. The manifest is saved only when every PUT succeeded.
 * - The local base records only keys this run actually synced. Failed,
 *   skipped, and divergent keys keep their old base, so the next diff
 *   retries them instead of adopting an unproven side.
 * - Diverged-both-sides is a conflict (remote copy preserved next to the
 *   local file), never a silent overwrite.
 * - Blobs are sealed like sessions (the pull path always decrypts), and
 *   every pulled byte stream is hash-verified and size-bounded before it
 *   touches disk.
 */
import { createHash } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import { lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync, utimesSync } from "node:fs";
import { keyFromEnv, openBounded, seal } from "./crypto.js";
import { EtagMismatchError, S3, type ObjectStore, type S3Config } from "./s3.js";
import {
  blobObjectKey,
  HEADER_PREFIX_BYTES,
  blobRefsIn,
  bucketDirForCwd,
  canonicalProjectKey,
  parseSessionHeaderPrefix,
  sessionLogicalId,
  sessionObjectKey,
  type KeyOptions,
  type PathMapEntry,
} from "./keys.js";
import {
  diffWithBase,
  loadLocalState,
  loadRemoteManifest,
  markSynced,
  saveRemoteManifest,
  scanLocalSessions,
  writeFileAtomic,
  type LocalFile,
  type ManifestEntry,
} from "./store.js";

/** Hard cap on session plaintext (zip-bomb defense; sessions can be large). */
export const SESSION_MAX_BYTES = 512 * 1024 * 1024;


export interface SyncConfig {
  s3: S3Config;
  /** Bucket prefix, always ends with "/". Default "omp-sync/". */
  prefix: string;
  autoPush: boolean;
  autoPull: boolean;
  /** Debounce for turn_end auto-push. Default 5000ms. */
  debounceMs: number;
  includeBlobs: boolean;
  /** Blobs larger than this are skipped with a warning. Default 32 MiB. */
  maxBlobBytes: number;
  pathMap: PathMapEntry[];
  resolvedFrom: string;
}

export interface AgentPaths {
  agentDir: string;
  sessionsRoot: string;
  blobsRoot: string;
  home: string;
  tmpdir: string;
}

const DEFAULT_PREFIX = "omp-sync/";
const ENC_UTF8 = (s: string): Buffer => Buffer.from(s, "utf-8");
const sha256hex = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

/**
 * Resolve the omp agent directory. Order: explicit env override, the host's
 * own answer (profiles included), on-disk probe, default. Never guesses
 * silently — doctor prints the result. omp-only: no other agent flavor is
 * ever probed or defaulted to.
 */
export function resolveAgentDir(host?: { getAgentDir?: () => string }): string {
  const env = process.env.PI_CODING_AGENT_DIR?.trim();
  if (env) return env;
  try {
    const fromHost = host?.getAgentDir?.();
    if (typeof fromHost === "string" && fromHost.trim()) return fromHost.trim();
  } catch {
    /* host answered with a throw; fall through to probing */
  }
  const omp = join(homedir(), ".omp", "agent");
  try {
    if (statSync(join(omp, "sessions")).isDirectory()) return omp;
  } catch {
    /* fresh machine */
  }
  return omp;
}

/**
 * Resolve the sessions root the way omp does: when XDG_DATA_HOME is set and
 * omp's XDG data dir ($XDG_DATA_HOME/omp) already exists, omp keeps sessions
 * under it — a hardcoded <agentDir>/sessions would read/write a tree the
 * host never discovers. Probe once per call; fall back to the default.
 */
function ompSessionsRoot(agentDir: string): string {
  const xdg = process.env.XDG_DATA_HOME?.trim();
  if (xdg && xdg.startsWith("/")) {
    const candidate = join(xdg, "omp");
    try {
      if (statSync(join(candidate, "sessions")).isDirectory()) return join(candidate, "sessions");
      if (statSync(candidate).isDirectory()) return join(candidate, "sessions");
    } catch {
      /* omp not XDG-redirected here */
    }
  }
  return join(agentDir, "sessions");
}

export function agentPaths(agentDir: string): AgentPaths {
  return {
    agentDir,
    sessionsRoot: ompSessionsRoot(agentDir),
    blobsRoot: join(agentDir, "blobs"),
    home: homedir(),
    tmpdir: tmpdir(),
  };
}

function keyOptions(paths: AgentPaths, cfg: SyncConfig): KeyOptions {
  return { home: paths.home, tmpdir: paths.tmpdir, pathMap: cfg.pathMap };
}

function idForFile(paths: AgentPaths, cfg: SyncConfig) {
  const ko = keyOptions(paths, cfg);
  return (filename: string, headerCwd: string | null): { id: string; canonical: string } => {
    if (headerCwd) {
      const canonical = canonicalProjectKey(headerCwd, ko);
      return { id: sessionLogicalId(canonical, filename), canonical };
    }
    // Header unreadable: keep the file addressable under an explicit
    // unknown/ namespace instead of dropping it from sync.
    const canonical = "unknown/bucket";
    return { id: sessionLogicalId(canonical, filename), canonical };
  };
}

/** Load config from <agentDir>/omp-sync.local.json with OMP_SYNC_* env overrides. */
export function loadSyncConfig(agentDir: string): SyncConfig | null {
  const env = process.env;
  let f: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(readFileSync(join(agentDir, "omp-sync.local.json"), "utf-8"));
    // A valid-JSON scalar (null, string, array) is not a config object.
    // Reject it here so recovery commands keep working instead of throwing
    // on the first field access below.
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      f = parsed as Record<string, unknown>;
    }
  } catch {
    /* no file or unparsable */
  }
  const str = (fileKey: string, envKey: string): string | undefined => {
    const e = env[envKey];
    if (typeof e === "string" && e) return e;
    const v = f[fileKey];
    return typeof v === "string" && v ? v : undefined;
  };
  const endpoint = str("endpoint", "OMP_SYNC_ENDPOINT");
  const bucket = str("bucket", "OMP_SYNC_BUCKET");
  const region = str("region", "OMP_SYNC_REGION") ?? "auto";
  const accessKeyId = str("accessKeyId", "OMP_SYNC_ACCESS_KEY_ID");
  const secretAccessKey = str("secretAccessKey", "OMP_SYNC_SECRET_ACCESS_KEY");
  if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) return null;

  const num = (fileKey: string, envKey: string, def: number): number => {
    const raw = env[envKey] ?? f[fileKey];
    const n = typeof raw === "number" ? raw : typeof raw === "string" ? Number(raw) : NaN;
    return Number.isFinite(n) && n > 0 ? n : def;
  };
  const bool = (fileKey: string, envKey: string, def: boolean): boolean => {
    const raw = env[envKey] ?? f[fileKey];
    if (typeof raw === "boolean") return raw;
    if (typeof raw === "string") return raw === "1" || raw.toLowerCase() === "true";
    return def;
  };
  let prefix = str("prefix", "OMP_SYNC_PREFIX") ?? DEFAULT_PREFIX;
  if (!prefix.endsWith("/")) prefix += "/";
  const pathMapRaw = env["OMP_SYNC_PATHMAP"] ?? f["pathMap"];
  let pathMap: PathMapEntry[] = [];
  try {
    const parsed: unknown = typeof pathMapRaw === "string" ? JSON.parse(pathMapRaw) : (pathMapRaw ?? []);
    if (Array.isArray(parsed)) {
      pathMap = parsed
        .filter((e): e is PathMapEntry => !!e && typeof (e as PathMapEntry).from === "string" && typeof (e as PathMapEntry).to === "string")
        .map((e) => ({ from: e.from, to: e.to }));
    }
  } catch {
    pathMap = [];
  }
  return {
    s3: { endpoint, bucket, region, accessKeyId, secretAccessKey, timeoutMs: num("timeoutMs", "OMP_SYNC_TIMEOUT_MS", 15_000) },
    prefix,
    autoPush: bool("autoPush", "OMP_SYNC_AUTO_PUSH", true),
    autoPull: bool("autoPull", "OMP_SYNC_AUTO_PULL", false),
    debounceMs: num("debounceMs", "OMP_SYNC_DEBOUNCE_MS", 5000),
    includeBlobs: bool("includeBlobs", "OMP_SYNC_BLOBS", true),
    maxBlobBytes: num("maxBlobBytes", "OMP_SYNC_MAX_BLOB_BYTES", 32 * 1024 * 1024),
    pathMap,
    resolvedFrom: (() => {
      try {
        readFileSync(join(agentDir, "omp-sync.local.json"));
        return "file";
      } catch {
        return "env";
      }
    })(),
  };
}

export function keyFromEnvOrThrow(): Buffer {
  const raw = process.env.OMP_SYNC_ENCRYPTION_KEY;
  if (!raw) throw new Error("OMP_SYNC_ENCRYPTION_KEY not set. Generate with: openssl rand -base64 32");
  return keyFromEnv(raw);
}

export interface SyncReport {
  pushed: number;
  pulled: number;
  conflicts: number;
  upToDate: number;
  skipped: number;
  blobsPushed: number;
  blobsPulled: number;
  errors: string[];
  /** Non-fatal notices (skipped files and why). Never blocks manifest/base. */
  warnings: string[];
}

function emptyReport(): SyncReport {
  return { pushed: 0, pulled: 0, conflicts: 0, upToDate: 0, skipped: 0, blobsPushed: 0, blobsPulled: 0, errors: [], warnings: [] };
}

/** Guard: a remote-derived relative path must not escape its parent dir. */
function assertSafeRel(rel: string, what: string): void {
  if (rel.split(/[\\/]/).some((seg) => seg === "" || seg === "." || seg === "..")) {
    throw new Error(`unsafe ${what}: ${rel}`);
  }
}

/**
 * Refuse bucket directories that escape the managed sessions root. Lexical
 * checks cannot see symlinks: an attacker- or accident-planted symlink at
 * <sessionsRoot>/<bucket> would redirect mkdir/write/rename outside the
 * root. Only existing paths can be links; absent paths are created under
 * sessionsRoot itself, whose own reality is verified once per call.
 */
function assertContainedBucket(sessionsRoot: string, destDir: string): void {
  let st;
  try {
    st = lstatSync(destDir);
  } catch {
    return; // absent: created fresh under the (verified) sessions root below
  }
  if (st.isSymbolicLink()) throw new Error(`refusing symlinked bucket dir: ${destDir}`);
  const realRoot = realpathSync(sessionsRoot);
  const realDest = realpathSync(destDir);
  if (realDest !== realRoot && !realDest.startsWith(realRoot + sep)) {
    throw new Error(`refusing bucket dir escaping sessions root: ${destDir}`);
  }
}
/**
 * Verify the upload buffer still carries the scanned header identity.
 * Returns a warning when the header was rewritten between scan and read
 * (project moved/renamed) — the caller skips instead of publishing fresh
 * bytes under a stale project identity.
 */
export function snapshotIdentity(plain: Buffer, scanCwd: string | null): string | null {
  const fresh = parseSessionHeaderPrefix(plain.subarray(0, Math.min(plain.length, HEADER_PREFIX_BYTES)).toString("utf-8")).cwd;
  if ((fresh ?? null) === (scanCwd ?? null)) return null;
  return "header changed between scan and upload — skipped, next push rescans";
}

export interface PushOptions {
  agentDir: string;
  cfg: SyncConfig;
  /** Restrict uploads to one local file (turn_end / shutdown fast path). */
  onlyAbsPath?: string;
  /** Injected store (tests). Defaults to a live S3 client. */
  store?: ObjectStore;
}
interface UploadedEntry extends ManifestEntry {
  plain: Buffer;
}

export async function pushSync({ agentDir, cfg, onlyAbsPath, store }: PushOptions): Promise<SyncReport> {
  const paths = agentPaths(agentDir);
  const s3 = store ?? new S3(cfg.s3);
  const encKey = keyFromEnvOrThrow();
  const report = emptyReport();

  const full = await scanLocalSessions(paths.sessionsRoot, idForFile(paths, cfg));
  if (!full.length) throw new Error(`no local sessions under ${paths.sessionsRoot}`);
  if (onlyAbsPath && !full.some((f) => f.absPath === onlyAbsPath)) {
    report.skipped++;
    return report; // file already gone (fresh session never materialized); touch nothing
  }
  const remote = await loadRemoteManifest(s3, cfg.prefix, encKey);
  const base = loadLocalState(agentDir).lastSynced;
  const fullDiff = diffWithBase(full, remote?.manifest ?? null, base);
  report.upToDate = onlyAbsPath ? 0 : fullDiff.upToDate;

  const toUpload = onlyAbsPath ? fullDiff.toPush.filter((f) => f.absPath === onlyAbsPath) : fullDiff.toPush;
  const uploaded: UploadedEntry[] = [];
  for (const e of toUpload) {
    let plain: Buffer;
    try {
      plain = readFileSync(e.absPath);
    } catch (err) {
      // A session file can vanish between scan and push (active rotation).
      // It left the local view: skip it AND keep it out of the manifest.
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        report.skipped++;
        continue;
      }
      report.errors.push(`push ${e.id}: ${String(err)}`);
      continue;
    }
    // Metadata describes the bytes actually uploaded, not the scan snapshot:
    // the live file may have grown between scan and read.
    let mtime = e.mtime;
    try {
      mtime = statSync(e.absPath).mtimeMs;
    } catch {
      report.skipped++;
      continue; // vanished after read; do not publish it
    }
    const drifted = snapshotIdentity(plain, e.headerCwd);
    if (drifted) {
      report.skipped++;
      report.warnings.push(`push ${e.id}: ${drifted}`);
      continue;
    }
    // Content-addressed object key: objects are immutable and create-only,
    // so a failed push can never wedge the previous generation. AAD binds
    // the ciphertext to this exact object key.
    const sha = sha256hex(plain);
    const objKey = sessionObjectKey(cfg.prefix, e.canonical, sha);
    try {
      try {
        await s3.putObject(objKey, seal(plain, encKey, ENC_UTF8(objKey)).body, "application/octet-stream", {
          ifNoneMatch: true,
        });
      } catch (err) {
        // Already there with identical bytes (concurrent same-content push):
        // adopt it instead of failing. Anything else is a real error.
        if (!(err instanceof EtagMismatchError)) throw err;
        const live = await s3.headObject(objKey).catch(() => null);
        if (!live) throw err;
      }
      uploaded.push({ id: e.id, key: objKey, sha256: sha, size: plain.length, mtime, cwd: e.headerCwd, canonical: e.canonical, plain });
      report.pushed++;
    } catch (err) {
      report.errors.push(`push ${e.id}: ${String(err)}`);
    }
  }
  // The manifest must never reference objects that never landed: any PUT
  // failure aborts before blob phase and manifest write alike.
  if (report.errors.length) return report;

  if (cfg.includeBlobs) {
    await pushBlobsFor(s3, cfg, paths, encKey, uploaded, report);
    if (report.errors.length) return report;
  }

  // Merge truthfully by logical id: untouched ids pass through verbatim
  // (even toPull and conflict ids — the objects behind them are unchanged);
  // only uploaded ids are replaced. Remote-only ids are HEAD-verified: a
  // 404 prunes a genuinely deleted object, while any other HEAD failure
  // KEEPS the entry (a sick network must not delete the index).
  const merged = new Map((remote?.manifest.entries ?? []).map((en) => [en.id, en]));
  for (const u of uploaded) {
    const { plain: _plain, ...entry } = u;
    merged.set(u.id, entry);
  }
  const localIds = new Set(full.map((f) => f.id));
  const uploadedIds = new Set(uploaded.map((u) => u.id));
  for (const [id, en] of merged) {
    if (uploadedIds.has(id) || localIds.has(id)) continue;
    try {
      const live = await s3.headObject(en.key);
      if (!live) merged.delete(id);
    } catch (err) {
      report.errors.push(`orphan check ${id}: ${String(err)} — entry kept`);
    }
  }
  const entries = [...merged.values()];
  // Scope the CAS retry to uploaded ids: on a 412 only our ids overlay
  // the winner, disjoint concurrent updates survive.
  await saveRemoteManifest(s3, cfg.prefix, { version: 1, updatedAt: Date.now(), entries }, encKey, remote?.etag, 3, uploadedIds);
  markSynced(
    agentDir,
    uploaded.map((u) => ({ id: u.id, sha256: u.sha256 })),
  );
  return report;
}

/**
 * Compare a pull destination against the scan snapshot. Returns an error
 * message when the local file moved under us (or appeared unannounced),
 * null when it is safe to overwrite.
 */
export function revalidateLocal(dest: string, byAbsPath: Map<string, LocalFile>): string | null {
  const scanned = byAbsPath.get(dest);
  let cur: { size: number; mtimeMs: number } | null = null;
  try {
    const st = statSync(dest);
    cur = { size: st.size, mtimeMs: st.mtimeMs };
  } catch {
    cur = null;
  }
  if (cur && (!scanned || cur.size !== scanned.size || cur.mtimeMs !== scanned.mtime)) {
    return "local file changed during pull — skipped, retry to adopt either side";
  }
  return null;
}

export interface PullOptions {
  agentDir: string;
  cfg: SyncConfig;
  /** Never touch these local files (e.g. the currently open session). */
  skipAbsPaths?: Set<string>;
  /** Injected store (tests). Defaults to a live S3 client. */
  store?: ObjectStore;
}

export async function pullSync({ agentDir, cfg, skipAbsPaths, store }: PullOptions): Promise<SyncReport> {
  const paths = agentPaths(agentDir);
  const s3 = store ?? new S3(cfg.s3);
  const encKey = keyFromEnvOrThrow();
  const report = emptyReport();

  const local = await scanLocalSessions(paths.sessionsRoot, idForFile(paths, cfg));
  const byAbsPath = new Map(local.map((f) => [f.absPath, f]));
  const remote = await loadRemoteManifest(s3, cfg.prefix, encKey);
  if (!remote) throw new Error("remote manifest not found — nothing to pull");
  const base = loadLocalState(agentDir).lastSynced;
  const d = diffWithBase(local, remote.manifest, base);
  report.upToDate = d.upToDate;

  const ko = keyOptions(paths, cfg);
  for (const e of d.toPull) {
    try {
      const got = await s3.getObject(e.key);
      if (!got) {
        report.errors.push(`pull ${e.id}: 404`);
        continue;
      }
      const plain = await openBounded({ body: got.body }, encKey, SESSION_MAX_BYTES, ENC_UTF8(e.key));
      if (sha256hex(plain) !== e.sha256) {
        report.errors.push(`pull ${e.id}: plaintext hash mismatches manifest — object swapped or corrupt, not written`);
        continue;
      }
      // Destination: the host's managed sessions bucket for this header cwd.
      // The filename comes from the logical id, never from the object key.
      // Verbatim project directories are never written to.
      const destDir = e.cwd
        ? join(paths.sessionsRoot, bucketDirForCwd(e.cwd, ko))
        : targetDirForUnknown(paths, e.key);
      const filename = e.id.slice(e.id.lastIndexOf("/") + 1);
      assertSafeRel(filename, "session filename");
      assertSafeRel(destDir === paths.sessionsRoot ? "." : destDir.slice(paths.sessionsRoot.length + 1) || ".", "bucket dir");
      const dest = join(destDir, filename);
      if (skipAbsPaths?.has(dest)) {
        report.skipped++;
        continue;
      }
      // Revalidate against the scan right before any network I/O and again
      // right before the write: the host may append at any moment, and
      // overwriting fresher local bytes with older remote ones is data loss.
      // A destination absent at scan but present now counts as changed too
      // (never overwrite a file we never saw).
      const moved = revalidateLocal(dest, byAbsPath);
      if (moved) {
        report.errors.push(`pull ${e.id}: ${moved}`);
        continue;
      }
      // Blobs resolve BEFORE the session file lands: an id whose blobs
      // cannot be fetched stays fully unapplied (no write, no base), so
      // the next pull retries it instead of calling it agreed.
      if (cfg.includeBlobs) {
        const errorsBefore = report.errors.length;
        await pullBlobsFor(s3, cfg, paths, encKey, [plain], report);
        if (report.errors.length !== errorsBefore) {
          report.errors.push(`pull ${e.id}: skipped, blob resolution failed`);
          continue;
        }
        const movedAfterBlobs = revalidateLocal(dest, byAbsPath);
        if (movedAfterBlobs) {
          report.errors.push(`pull ${e.id}: ${movedAfterBlobs}`);
          continue;
        }
      }
      // Containment last: a symlinked bucket dir would redirect this write
      // outside the managed root. Checked after revalidation so the common
      // case stays a single stat.
      assertContainedBucket(paths.sessionsRoot, destDir);
      mkdirSync(destDir, { recursive: true });
      writeFileAtomic(dest, plain);
      // Restore the source mtime so both views agree (otherwise the write
      // stamps now() and the next diff sees a phantom change).
      utimesSync(dest, e.mtime / 1000, e.mtime / 1000);
      markSynced(agentDir, [{ id: e.id, sha256: e.sha256 }]);
      report.pulled++;
    } catch (err) {
      report.errors.push(`pull ${e.id}: ${String(err)}`);
    }
  }

  // Both sides diverged: preserve the remote side next to the local file,
  // keep the local bytes untouched, and record the base so the next push
  // adopts local without re-conflicting. The conflict copy becomes a new
  // local session file and syncs up on the next push like any other file.
  for (const c of d.conflicts) {
    try {
      const got = await s3.getObject(c.remote.key);
      if (!got) {
        report.errors.push(`conflict ${c.remote.key}: 404`);
        continue;
      }
      const plain = await openBounded({ body: got.body }, encKey, SESSION_MAX_BYTES, ENC_UTF8(c.remote.key));
      if (sha256hex(plain) !== c.remote.sha256) {
        report.errors.push(`conflict ${c.remote.key}: plaintext hash mismatches manifest — copy not written`);
        continue;
      }
      // The copy's blob attachments resolve BEFORE it lands: a preserved
      // session with dangling references would converge as up-to-date on
      // the next push and never fetch them again.
      if (cfg.includeBlobs) {
        const errorsBefore = report.errors.length;
        await pullBlobsFor(s3, cfg, paths, encKey, [plain], report);
        if (report.errors.length !== errorsBefore) {
          report.errors.push(`conflict ${c.remote.id}: skipped, blob resolution failed`);
          continue;
        }
      }
      const destDir = dirname(c.local.absPath);
      const stem = c.local.filename.replace(/\.jsonl$/, "");
      assertSafeRel(stem, "session filename");
      assertContainedBucket(paths.sessionsRoot, destDir);
      const dest = join(destDir, `${stem}.conflict-${Date.now()}.jsonl`);
      writeFileAtomic(dest, plain);
      utimesSync(dest, c.remote.mtime / 1000, c.remote.mtime / 1000);
      // Record the REMOTE side as the base, not the local one: the remote
      // copy is preserved on disk, and the local file still needs uploading.
      // (Recording local here would invert the next diff into "remote
      // changed, pull" and clobber the local side we just preserved.)
      markSynced(agentDir, [{ id: c.remote.id, sha256: c.remote.sha256 }]);
      report.conflicts++;
    } catch (err) {
      report.errors.push(`conflict ${c.remote.key}: ${String(err)}`);
    }
  }
  return report;
}

/**
 * Fallback target when the header cwd is unknown: park under a namespaced
 * bucket in the sessions root so the file stays visible and resumable.
 * Deliberately NOT reconstructed from the canonical key segment (lossy).
 */
function targetDirForUnknown(paths: AgentPaths, key: string): string {
  const canon = key.split("/sessions/")[1]?.split("/").slice(0, -1).join("-") || "unknown";
  assertSafeRel(canon, "bucket segment");
  return join(paths.sessionsRoot, `unknown-${canon}`);
}

async function pushBlobsFor(
  s3: ObjectStore,
  cfg: SyncConfig,
  paths: AgentPaths,
  encKey: Buffer,
  uploaded: UploadedEntry[],
  report: SyncReport,
): Promise<void> {
  const refs = new Set<string>();
  for (const u of uploaded) for (const h of blobRefsIn(u.plain)) refs.add(h);
  if (!refs.size) return;
  const remote = new Set((await s3.listObjects(`${cfg.prefix}blobs/`).catch(() => [])).map((o) => o.key));
  for (const h of refs) {
    const objectKey = blobObjectKey(cfg.prefix, h);
    if (remote.has(objectKey)) continue;
    const abs = join(paths.blobsRoot, h);
    let raw: Buffer;
    try {
      raw = readFileSync(abs);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      report.errors.push(`blob ${h}: ${String(err)}`);
      continue;
    }
    if (raw.length > cfg.maxBlobBytes) {
      // Over-cap is a policy outcome, not a failure: warn and keep going so
      // the session still publishes. Machines pulling it will refuse the
      // session with an explicit missing-oversized-blob error instead of
      // wedging this push forever.
      report.warnings.push(`blob ${h}: ${raw.length} bytes exceeds maxBlobBytes (${cfg.maxBlobBytes}) — not uploaded; raise the limit to sync its sessions`);
      continue;
    }
    try {
      // Sealed like sessions: every pull path decrypts, so plaintext here
      // would 404-into-GCM-failure on the other side. AAD binds hash<->bytes.
      await s3.putObject(objectKey, seal(raw, encKey, ENC_UTF8(objectKey)).body, "application/octet-stream");
      const head = await s3.headObject(objectKey).catch(() => null);
      if (!head) report.errors.push(`blob ${h}: uploaded but HEAD-verification failed`);
      else report.blobsPushed++;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      report.errors.push(`blob ${h}: ${String(err)}`);
    }
  }
}

async function pullBlobsFor(
  s3: ObjectStore,
  cfg: SyncConfig,
  paths: AgentPaths,
  encKey: Buffer,
  plains: Buffer[],
  report: SyncReport,
): Promise<void> {
  const refs = new Set<string>();
  for (const p of plains) for (const h of blobRefsIn(p)) refs.add(h);
  for (const h of refs) {
    const objectKey = blobObjectKey(cfg.prefix, h);
    const abs = join(paths.blobsRoot, h);
    try {
      if (statSync(abs).isFile()) continue;
    } catch {
      /* missing -> download */
    }
    try {
      const got = await s3.getObject(objectKey);
      if (!got) {
        report.errors.push(`blob ${h}: referenced by a session but missing remotely`);
        continue;
      }
      const plain = await openBounded({ body: got.body }, encKey, cfg.maxBlobBytes, ENC_UTF8(objectKey));
      if (sha256hex(plain) !== h) {
        report.errors.push(`blob ${h}: decrypted bytes mismatch their content-addressed name — not written`);
        continue;
      }
      mkdirSync(paths.blobsRoot, { recursive: true });
      writeFileAtomic(abs, plain);
      report.blobsPulled++;
    } catch (err) {
      report.errors.push(`blob ${h}: ${String(err)}`);
    }
  }
}

/** Full two-way blob reconcile (the `blobs` subcommand). */
export async function syncBlobs(agentDir: string, cfg: SyncConfig, store?: ObjectStore): Promise<SyncReport> {
  const paths = agentPaths(agentDir);
  const s3 = store ?? new S3(cfg.s3);
  const encKey = keyFromEnvOrThrow();
  const report = emptyReport();
  if (!cfg.includeBlobs) {
    report.errors.push("blobs disabled by config (includeBlobs=false)");
    return report;
  }
  let localHashes: string[] = [];
  try {
    localHashes = readdirSync(paths.blobsRoot).filter((f) => /^[0-9a-f]{64}$/.test(f));
  } catch {
    mkdirSync(paths.blobsRoot, { recursive: true });
  }
  const remoteObjs = await s3.listObjects(`${cfg.prefix}blobs/`);
  const remoteHashes = new Set(remoteObjs.map((o) => o.key.slice(o.key.lastIndexOf("/") + 1)));
  const localSet = new Set(localHashes);
  for (const h of localHashes) {
    if (remoteHashes.has(h)) continue;
    const objectKey = blobObjectKey(cfg.prefix, h);
    const abs = join(paths.blobsRoot, h);
    let raw: Buffer;
    try {
      raw = readFileSync(abs);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      report.errors.push(`blob ${h}: ${String(err)}`);
      continue;
    }
    if (raw.length > cfg.maxBlobBytes) {
      report.errors.push(`blob ${h}: exceeds maxBlobBytes, skipped`);
      continue;
    }
    try {
      await s3.putObject(objectKey, seal(raw, encKey, ENC_UTF8(objectKey)).body);
      const head = await s3.headObject(objectKey).catch(() => null);
      if (!head) report.errors.push(`blob ${h}: uploaded but HEAD-verification failed`);
      else report.blobsPushed++;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") continue;
      report.errors.push(`blob ${h}: ${String(err)}`);
    }
  }
  for (const h of remoteHashes) {
    if (localSet.has(h)) continue;
    const objectKey = blobObjectKey(cfg.prefix, h);
    try {
      const got = await s3.getObject(objectKey);
      if (!got) continue;
      const plain = await openBounded({ body: got.body }, encKey, cfg.maxBlobBytes, ENC_UTF8(objectKey));
      if (sha256hex(plain) !== h) {
        report.errors.push(`blob ${h}: decrypted bytes mismatch their content-addressed name — not written`);
        continue;
      }
      writeFileAtomic(join(paths.blobsRoot, h), plain);
      report.blobsPulled++;
    } catch (err) {
      report.errors.push(`blob ${h}: ${String(err)}`);
    }
  }
  return report;
}

export interface StatusResult {
  agentDir: string;
  prefix: string;
  localCount: number;
  remoteCount: number | null;
  toPush: number;
  toPull: number;
  conflicts: number;
  upToDate: number;
}

/** Status: local vs remote diff without changing anything. */
export async function statusSync(agentDir: string, cfg: SyncConfig, store?: ObjectStore): Promise<StatusResult> {
  const paths = agentPaths(agentDir);
  const s3 = store ?? new S3(cfg.s3);
  const encKey = keyFromEnvOrThrow();
  const local = await scanLocalSessions(paths.sessionsRoot, idForFile(paths, cfg));
  const remote = await loadRemoteManifest(s3, cfg.prefix, encKey);
  const d = diffWithBase(local, remote?.manifest ?? null, loadLocalState(agentDir).lastSynced);
  return {
    agentDir,
    prefix: cfg.prefix,
    localCount: local.length,
    remoteCount: remote?.manifest.entries.length ?? null,
    toPush: d.toPush.length,
    toPull: d.toPull.length,
    conflicts: d.conflicts.length,
    upToDate: d.upToDate,
  };
}

export interface DoctorReport {
  agentDir: string;
  configOk: boolean;
  configSource: "file" | "env" | "none";
  keyOk: boolean;
  pingOk: boolean;
  localCount: number;
  remoteManifest: boolean;
  remoteCount: number;
  prefix: string;
  errors: string[];
}

/** Doctor: read-only diagnostic. No lock, no writes. */
export async function doctorSync(agentDir: string, store?: ObjectStore): Promise<DoctorReport> {
  const paths = agentPaths(agentDir);
  const rep: DoctorReport = {
    agentDir,
    configOk: false,
    configSource: "none",
    keyOk: false,
    pingOk: false,
    localCount: 0,
    remoteManifest: false,
    remoteCount: 0,
    prefix: DEFAULT_PREFIX,
    errors: [],
  };
  let hasFile = false;
  try {
    readFileSync(join(agentDir, "omp-sync.local.json"), "utf-8");
    hasFile = true;
  } catch {
    /* no file */
  }
  const hasEnv = Boolean(process.env.OMP_SYNC_ENDPOINT && process.env.OMP_SYNC_ACCESS_KEY_ID);
  rep.configSource = hasFile ? "file" : hasEnv ? "env" : "none";
  const cfg = loadSyncConfig(agentDir);
  if (!cfg) {
    rep.errors.push("config missing (need <agentDir>/omp-sync.local.json or OMP_SYNC_* env)");
    return rep;
  }
  rep.configOk = true;
  rep.prefix = cfg.prefix;

  try {
    keyFromEnvOrThrow();
    rep.keyOk = true;
  } catch (e) {
    rep.errors.push(`OMP_SYNC_ENCRYPTION_KEY: ${(e as Error).message}`);
  }

  const local = await scanLocalSessions(paths.sessionsRoot, idForFile(paths, cfg));
  rep.localCount = local.length;
  if (!local.length) rep.errors.push(`no local sessions under ${paths.sessionsRoot}`);

  if (!rep.keyOk) return rep;
  const s3 = store ?? new S3(cfg.s3);
  try {
    rep.pingOk = await s3.ping();
  } catch (e) {
    rep.errors.push(`ping ${cfg.s3.endpoint}: ${(e as Error).message}`);
    return rep;
  }
  if (!rep.pingOk) {
    rep.errors.push("bucket unreachable (check endpoint/bucket/region/credentials)");
    return rep;
  }
  try {
    const remote = await loadRemoteManifest(s3, cfg.prefix, keyFromEnvOrThrow());
    rep.remoteManifest = Boolean(remote);
    rep.remoteCount = remote?.manifest.entries.length ?? 0;
  } catch (e) {
    rep.errors.push(`manifest load: ${(e as Error).message}`);
  }
  return rep;
}

/** Redacted config summary for the `config` subcommand (never prints secrets). */
export function describeConfig(agentDir: string, cfg: SyncConfig): string[] {
  return [
    `agentDir:    ${agentDir}`,
    `sessions:    ${join(agentDir, "sessions")}`,
    `endpoint:    ${cfg.s3.endpoint}`,
    `bucket:      ${cfg.s3.bucket}`,
    `region:      ${cfg.s3.region}`,
    `prefix:      ${cfg.prefix}`,
    `source:      ${cfg.resolvedFrom}`,
    `autoPush:    ${cfg.autoPush} (debounce ${cfg.debounceMs}ms)`,
    `autoPull:    ${cfg.autoPull}`,
    `blobs:       ${cfg.includeBlobs} (max ${cfg.maxBlobBytes} bytes)`,
    `pathMap:     ${cfg.pathMap.length} entr${cfg.pathMap.length === 1 ? "y" : "ies"}`,
    ...cfg.pathMap.map((e) => `  ${e.from}  ->  ${e.to}`),
  ];
}
