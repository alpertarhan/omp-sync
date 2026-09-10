/**
 * Key scheme: S3 object keys derive from the session header's `cwd`,
 * never from the on-disk bucket directory name.
 *
 * Why: omp bucket names are lossy (`~/dev-bengu` and `~/dev/bengu` both
 * encode as `-dev-bengu`). The header `cwd` is the authoritative project
 * identity, so any two omp machines converge on the same keys for the
 * same project.
 *
 * Canonical project key: `home/<rel>` | `tmp/<rel>` | `abs/<sanitized>`,
 * where `home/` covers both local $HOME and foreign POSIX home shapes
 * (`/Users/<u>`, `/home/<u>`, `/root`) so sessions stay identical across
 * mac↔linux sync.
 * Object layout under the bucket prefix:
 *   <prefix>sessions/<canonical>/<filename>.enc
 *   <prefix>blobs/<sha256hex>
 *   <prefix>manifest.json          (one sealed blob)
 */
import { closeSync, openSync, readSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
export interface PathMapEntry {
  from: string;
  to: string;
}

export interface KeyOptions {
  home: string;
  tmpdir: string;
  pathMap?: PathMapEntry[];
}

/** Normalize separators for comparison (windows backslashes included). */
export function slash(p: string): string {
  return p.replace(/\\/g, "/");
}

/** Longest-prefix rewrite, e.g. different usernames across machines. */
export function applyPathMap(absPath: string, map?: PathMapEntry[]): string {
  if (!map?.length) return absPath;
  const p = slash(absPath);
  let best: PathMapEntry | undefined;
  for (const e of map) {
    const from = slash(e.from).replace(/\/+$/, "") + "/";
    if (p === slash(e.from).replace(/\/+$/, "") || p.startsWith(from)) {
      if (!best || from.length > slash(best.from).replace(/\/+$/, "").length + 1) best = e;
    }
  }
  if (!best) return absPath;
  const from = slash(best.from).replace(/\/+$/, "");
  const to = slash(best.to).replace(/\/+$/, "");
  const rest = p === from ? "" : p.slice(from.length);
  return to + rest;
}

function underDir(absPath: string, dir: string): string | null {
  const p = slash(absPath);
  const d = slash(dir).replace(/\/+$/, "");
  if (p === d) return "";
  if (p.startsWith(d + "/")) return p.slice(d.length + 1);
  return null;
}

/** Sanitize one path segment for S3-safe keys. */
function sanitizeSegment(seg: string): string {
  if (seg === "" || seg === "." || seg === "..") return "-";
  return seg.replace(/[^A-Za-z0-9._-]+/g, "-");
}

/**
 * Canonical project key for a session cwd. Deterministic across mac/linux
 * for anything under $HOME — including a FOREIGN home shape: session files
 * travel verbatim, so a cwd written on macOS (`/Users/u/...`) must encode
 * identically when the file is rescanned on Linux (`/home/u/...` local
 * home) and vice versa. Relying on the local $HOME alone breaks that round
 * trip: the foreign shape falls to `abs/...` and the logical id diverges,
 * so every pull re-pushes as a "new" session forever. Temp-root and other
 * absolute paths stay host-shaped (documented: they cannot be reconciled
 * across OSes).
 */
export function canonicalProjectKey(cwd: string, opts: KeyOptions): string {
  const mapped = applyPathMap(cwd, opts.pathMap);
  const homeRel = underDir(mapped, opts.home);
  if (homeRel !== null) {
    const segs = homeRel === "" ? [] : homeRel.split("/").map(sanitizeSegment);
    return ["home", ...segs].join("/");
  }
  const tmpRel = underDir(mapped, opts.tmpdir);
  if (tmpRel !== null) {
    const segs = tmpRel === "" ? [] : tmpRel.split("/").map(sanitizeSegment);
    return ["tmp", ...segs].join("/");
  }
  const foreignHome = foreignHomeRelative(mapped);
  if (foreignHome !== null) {
    const segs = foreignHome === "" ? [] : foreignHome.split("/").map(sanitizeSegment);
    return ["home", ...segs].join("/");
  }
  const stripped = slash(mapped).replace(/^\/+/, "");
  const segs = stripped === "" ? [] : stripped.split("/").map(sanitizeSegment);
  return ["abs", ...segs].join("/");
}

/**
 * Home-relative part of a cwd that uses a STANDARD POSIX home root other
 * than this machine's: `/Users/<u>/rest`, `/home/<u>/rest`, `/root/rest`
 * (username dropped — it already is for local-home paths). Purely a
 * function of the path string, so every machine classifies the same cwd
 * identically. Returns null when the path is not home-shaped.
 */
export function foreignHomeRelative(p: string): string | null {
  const m = slash(p).match(/^\/(?:Users\/[^/]+|home\/[^/]+|root)(?:\/(.*))?$/);
  return m ? (m[1] ?? "") : null;
}

export interface BucketOptions extends KeyOptions {
  /** Resolve symlinks (e.g. /tmp -> /private/tmp) before encoding. Default true. */
  canonicalize?: boolean;
}

function canonicalize(p: string, enabled: boolean): string {
  if (!enabled) return resolve(p);
  try {
    return realpathSync(p);
  } catch {
    return resolve(p); // may not exist (yet) on this machine
  }
}

/**
 * The on-disk session bucket directory for a cwd, mirroring omp's own
 * encoder (session-paths.ts): `-<home-relative>`, `-tmp-<temp-relative>`,
 * `--<absolute>--` otherwise, with `[/\\:]` folded to `-`.
 *
 * A cwd from another machine's home (`/Users/u/...` seen on Linux, or the
 * reverse) folds into the same `-<home-relative>` bucket omp itself uses
 * for the equivalent local project, so pulled sessions sit next to native
 * ones instead of accumulating in `--Users-u-...--` quarantine dirs.
 *
 * Pulls ALWAYS land under <sessionsRoot>/<bucketDir> — the only tree omp
 * discovers sessions from. Never the project working directory.
 */
export function bucketDirForCwd(cwd: string, opts: BucketOptions): string {
  const mapped = applyPathMap(cwd, opts.pathMap);
  const canon = canonicalize(mapped, opts.canonicalize ?? true);
  const home = canonicalize(opts.home, opts.canonicalize ?? true);
  const tmp = canonicalize(opts.tmpdir, opts.canonicalize ?? true);
  const homeRel = relative(home, canon);
  if (homeRel === "" || (!homeRel.startsWith("..") && !isAbsolute(homeRel))) {
    return homeRel === "" ? "-" : `-${homeRel.replace(/[/\\:]/g, "-")}`;
  }
  const tmpRel = relative(tmp, canon);
  if (tmpRel === "" || (!tmpRel.startsWith("..") && !isAbsolute(tmpRel))) {
    return tmpRel === "" ? "-tmp" : `-tmp-${tmpRel.replace(/[/\\:]/g, "-")}`;
  }
  const foreignHome = foreignHomeRelative(canon);
  if (foreignHome !== null) return `-${foreignHome.replace(/[/\\:]/g, "-")}`;
  return `--${slash(canon).replace(/^\/+/, "").replace(/[/\\:]/g, "-")}--`;
}

/**
 * Stable logical identity of a session: project + filename. Never changes
 * across edits; diff and base state match on this, never on object keys.
 */
export function sessionLogicalId(canonical: string, filename: string): string {
  if (filename.split(/[\\/]/).some((s) => s === "" || s === "." || s === "..")) {
    throw new Error(`unsafe session filename: ${filename}`);
  }
  return `sessions/${canonical}/${filename}`;
}

/**
 * Immutable object key for sealed session bytes: content-addressed, so an
 * object is never overwritten. A failed push leaves the previous generation
 * intact and pulls can never pair a manifest hash with foreign bytes.
 */
export function sessionObjectKey(prefix: string, canonical: string, sha256hex: string): string {
  if (!/^[0-9a-f]{64}$/.test(sha256hex)) throw new Error(`invalid content hash: ${sha256hex}`);
  return `${prefix}sessions/${canonical}/${sha256hex}.enc`;
}

/** S3 key for one content-addressed blob. */
export function blobObjectKey(prefix: string, hash: string): string {
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`invalid blob hash: ${hash}`);
  return `${prefix}blobs/${hash}`;
}

export function manifestObjectKey(prefix: string): string {
  return `${prefix}manifest.json`;
}

/**
 * Read a session header's cwd without loading the whole file: a bounded
 * 8 KiB prefix read, so multi-hundred-megabyte transcripts cost nothing
 * at scan time. Handles files with the 256-byte title slot (first line
 * `{"type":"title",...}`) as well as slot-less files.
 */
export function readSessionHeader(absPath: string): { cwd: string | null } {
  let fd: number | undefined;
  try {
    fd = openSync(absPath, "r");
    const buf = Buffer.alloc(HEADER_PREFIX_BYTES);
    const n = readSync(fd, buf, 0, buf.length, 0);
    return parseSessionHeaderPrefix(buf.subarray(0, n).toString("utf-8"));
  } catch {
    return { cwd: null };
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* descriptor hygiene only */
      }
    }
  }
}

export const HEADER_PREFIX_BYTES = 8192;

/** Parse a header prefix (see readSessionHeader). Exported for upload snapshots. */
export function parseSessionHeaderPrefix(head: string): { cwd: string | null } {
  const lines = head.split("\n");
  for (const line of lines.slice(0, 3)) {
    const t = line.trim();
    if (!t) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(t);
    } catch {
      continue;
    }
    if (typeof obj !== "object" || obj === null) continue;
    const rec = obj as Record<string, unknown>;
    if (rec["type"] === "title") continue; // fixed-width title slot line
    if (rec["type"] === "session") {
      return { cwd: typeof rec["cwd"] === "string" ? rec["cwd"] : null };
    }
    return { cwd: null }; // first real line isn't a header — unknown shape
  }
  return { cwd: null };
}

/** Content-addressed blob references inside session JSONL (`blob:sha256:<hex>`). */
export function blobRefsIn(content: Buffer | string): string[] {
  const text = typeof content === "string" ? content : content.toString("utf-8");
  const out = new Set<string>();
  const re = /blob:sha256:([0-9a-f]{64})/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) out.add(m[1]);
  return [...out];
}
