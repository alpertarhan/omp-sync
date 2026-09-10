/**
 * Engine tests against an in-memory FakeS3: manifest discipline, base-state
 * integrity, blob sealing, conflict preservation, failure atomicity, and
 * content-addressed generation safety (a failed push can never wedge the
 * previous generation).
 * No network, no clock tricks — all races are injected deterministically.
 */
import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, statSync, readdirSync, appendFileSync, symlinkSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import { randomBytes, createHash } from "node:crypto";
import { FakeS3 } from "./fake-s3.js";
import { loadLocalState, loadRemoteManifest, markSynced, saveRemoteManifest } from "../src/store.js";
import { bucketDirForCwd, canonicalProjectKey, sessionLogicalId, sessionObjectKey } from "../src/keys.js";
import { open, seal } from "../src/crypto.js";
import { agentPaths, pullSync, pushSync, revalidateLocal, snapshotIdentity, syncBlobs, type SyncConfig } from "../src/sync.js";

const HOME = homedir();
const TMP = tmpdir();
const KO = { home: HOME, tmpdir: TMP, pathMap: [] as { from: string; to: string }[] };
const KEY = randomBytes(32);
const KEY_B64 = KEY.toString("base64");
const CWDA = join(HOME, "dev", "x");
const CANON_A = canonicalProjectKey(CWDA, KO);
const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");
const lid = (filename: string): string => sessionLogicalId(CANON_A, filename);
const objKey = (filename: string, content: Buffer): string => sessionObjectKey("t/", CANON_A, sha(content));

let savedKey: string | undefined;
beforeEach(() => {
  savedKey = process.env.OMP_SYNC_ENCRYPTION_KEY;
  process.env.OMP_SYNC_ENCRYPTION_KEY = KEY_B64;
});
afterEach(() => {
  if (savedKey === undefined) delete process.env.OMP_SYNC_ENCRYPTION_KEY;
  else process.env.OMP_SYNC_ENCRYPTION_KEY = savedKey;
});

function makeAgent(): { dir: string; sessions: string; blobs: string } {
  const dir = mkdtempSync(join(tmpdir(), "omp-sync-e2e-"));
  const sessions = join(dir, "sessions");
  const blobs = join(dir, "blobs");
  mkdirSync(sessions, { recursive: true });
  return { dir, sessions, blobs };
}

function wipe(a: { dir: string }): void {
  rmSync(a.dir, { recursive: true, force: true });
}

function writeSession(sessions: string, bucket: string, filename: string, cwd: string, marker: string): string {
  const dir = join(sessions, bucket);
  mkdirSync(dir, { recursive: true });
  const abs = join(dir, filename);
  writeFileSync(
    abs,
    `{"type":"session","version":3,"id":"${marker}","cwd":${JSON.stringify(cwd)}}\n` +
      `{"type":"message","id":"m1","parentId":null,"timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"${marker}"}}\n`,
  );
  return abs;
}

function makeCfg(over: Partial<SyncConfig> = {}): SyncConfig {
  return {
    s3: { endpoint: "https://s3.example.com", bucket: "bkt", region: "auto", accessKeyId: "a", secretAccessKey: "s" },
    prefix: "t/",
    autoPush: false,
    autoPull: false,
    debounceMs: 10,
    includeBlobs: true,
    maxBlobBytes: 4 * 1024 * 1024,
    pathMap: [],
    resolvedFrom: "test",
    ...over,
  };
}

interface TestEntry {
  id: string;
  key: string;
  sha256: string;
  size: number;
  mtime: number;
  cwd: string | null;
  canonical: string;
}

async function readManifest(store: FakeS3, prefix: string): Promise<{ entries: TestEntry[]; etag?: string } | null> {
  const got = await store.getObject(`${prefix}manifest.json`);
  if (!got) return null;
  const aad = Buffer.from(`${prefix}manifest.json`, "utf-8");
  return { ...JSON.parse(open({ body: got.body }, KEY, aad).toString("utf-8")), etag: got.etag };
}

function ent(id: string, sha256: string, key?: string): TestEntry {
  return { id, key: key ?? `obj/${sha256}`, sha256, size: 1, mtime: 1, cwd: CWDA, canonical: CANON_A };
}

test("push uploads sessions, seals the manifest, records base, idempotent", async () => {
  const a = makeAgent();
  try {
    const abs = writeSession(a.sessions, "-dev-x", "f1.jsonl", CWDA, "one");
    const store = new FakeS3();
    const cfg = makeCfg();
    const r = await pushSync({ agentDir: a.dir, cfg, store });
    expect(r.errors).toEqual([]);
    expect(r.pushed).toBe(1);
    const id = lid("f1.jsonl");
    const key = objKey("f1.jsonl", readFileSync(abs));
    void id;
    expect(store.keys()).toContain(key);
    expect(store.keys()).toContain("t/manifest.json");
    const m = await readManifest(store, "t/");
    expect(m?.entries.map((e) => e.id)).toEqual([lid("f1.jsonl")]);
    const first = m?.entries[0];
    if (!first) throw new Error("manifest entry missing");
    expect(first.key).toBe(key);
    expect(loadLocalState(a.dir).lastSynced[lid("f1.jsonl")]).toBe(first.sha256);
    // Second push is a no-op.
    const r2 = await pushSync({ agentDir: a.dir, cfg, store });
    expect(r2.pushed).toBe(0);
    expect(r2.upToDate).toBe(1);
  } finally {
    wipe(a);
  }
});

test("cross-machine round trip: foreign home cwd keeps one stable id (mac <-> linux)", async () => {
  const mac = makeAgent();
  const lin = makeAgent();
  try {
    const store = new FakeS3();
    const cfg = makeCfg();
    // Session born on the "mac" under /Users/ersin — foreign to every other
    // machine's $HOME. No pathMap: convergence must be automatic.
    writeSession(mac.sessions, "-Projects-acme", "f1.jsonl", "/Users/ersin/Projects/acme", "mac-side");
    const r1 = await pushSync({ agentDir: mac.dir, cfg, store });
    expect(r1.errors).toEqual([]);
    expect(r1.pushed).toBe(1);
    // The "linux" machine pulls: the file lands in the native home bucket
    // (where omp looks for the equivalent local project), header cwd verbatim.
    const r2 = await pullSync({ agentDir: lin.dir, cfg, store });
    expect(r2.errors).toEqual([]);
    expect(r2.pulled).toBe(1);
    expect(readdirSync(lin.sessions)).toEqual(["-Projects-acme"]);
    expect(readFileSync(join(lin.sessions, "-Projects-acme", "f1.jsonl"), "utf-8")).toContain("mac-side");
    // Rescan + push from the pulling machine: the foreign header cwd must
    // re-encode to the SAME logical id — no quarantine bucket, no duplicate
    // abs/... entry, no push/pull loop.
    const r3 = await pushSync({ agentDir: lin.dir, cfg, store });
    expect(r3.errors).toEqual([]);
    expect(r3.pushed).toBe(0);
    expect(r3.upToDate).toBe(1);
    expect(readdirSync(lin.sessions)).toEqual(["-Projects-acme"]);
    const m = await readManifest(store, "t/");
    expect(m?.entries.map((e) => e.id)).toEqual(["sessions/home/Projects/acme/f1.jsonl"]);
  } finally {
    wipe(mac);
    wipe(lin);
  }
});

test("scoped push replaces only the uploaded id in the manifest", async () => {
  const a = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    const idN = lid("new.jsonl");
    const idR = lid("remote.jsonl");
    const idC = lid("conf.jsonl");
    writeSession(a.sessions, "-dev-x", "new.jsonl", CWDA, "new");
    writeSession(a.sessions, "-dev-x", "conf.jsonl", CWDA, "local-diverged");
    await store.putObject(`t/sessions/${CANON_A}/rr`, Buffer.from("dummy-remote-bytes"));
    await saveRemoteManifest(
      store,
      "t/",
      { version: 1, updatedAt: 1, entries: [ent(idR, "1".repeat(64), `t/sessions/${CANON_A}/rr`), ent(idC, "2".repeat(64))] },
      KEY,
    );
    markSynced(a.dir, [{ id: idC, sha256: "base-diverged" }]); // true conflict: base matches neither side
    const onlyN = join(a.sessions, "-dev-x", "new.jsonl");
    const r = await pushSync({ agentDir: a.dir, cfg, store, onlyAbsPath: onlyN });
    expect(r.errors).toEqual([]);
    expect(r.pushed).toBe(1);
    const m = await readManifest(store, "t/");
    const byId = new Map(m?.entries.map((e) => [e.id, e.sha256]));
    // Untouched ids pass through verbatim — the conflict is NOT resolved behind our back.
    expect(byId.get(idR)).toBe("1".repeat(64));
    expect(byId.get(idC)).toBe("2".repeat(64));
    expect(byId.has(idN)).toBe(true);
    // Base gains only the uploaded id; the pre-existing entry is preserved.
    const uploadedSha = byId.get(idN);
    if (!uploadedSha) throw new Error("uploaded id missing from manifest");
    expect(loadLocalState(a.dir).lastSynced).toEqual({ [idC]: "base-diverged", [idN]: uploadedSha });
  } finally {
    wipe(a);
  }
});

test("automatic blob uploads are sealed and round-trip", async () => {
  const a = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    const raw = Buffer.from("fake-image-bytes");
    const h = sha(raw); // content-addressed: filename MUST equal sha256(bytes)
    mkdirSync(a.blobs, { recursive: true });
    writeFileSync(join(a.blobs, h), raw);
    writeSession(a.sessions, "-dev-x", "img.jsonl", CWDA, `see blob:sha256:${h} here`);
    const r = await pushSync({ agentDir: a.dir, cfg, store });
    expect(r.errors).toEqual([]);
    expect(r.blobsPushed).toBe(1);
    const obj = await store.getObject(`t/blobs/${h}`);
    expect(obj).not.toBeNull();
    expect(obj?.body.equals(raw)).toBe(false); // sealed, not plaintext
    const back = open({ body: obj!.body }, KEY, Buffer.from(`t/blobs/${h}`, "utf-8"));
    expect(back.equals(raw)).toBe(true);
  } finally {
    wipe(a);
  }
});

test("session PUT failure publishes nothing and records nothing", async () => {
  const a = makeAgent();
  try {
    const cfg = makeCfg({ includeBlobs: false });
    const store = new FakeS3();
    // Fail every session-object PUT without knowing the content hash upfront.
    const origPut = store.putObject.bind(store);
    store.putObject = async (key, body, ct, opts) => {
      if (key.includes("/sessions/")) throw new Error(`injected PUT failure: ${key}`);
      return origPut(key, body, ct, opts);
    };
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, "x");
    const r = await pushSync({ agentDir: a.dir, cfg, store });
    expect(r.pushed).toBe(0);
    expect(r.errors.length).toBe(1);
    expect(store.keys()).toEqual([]);
    expect(loadLocalState(a.dir).lastSynced).toEqual({});
  } finally {
    wipe(a);
  }
});

test("blob PUT failure blocks manifest and base despite uploaded sessions", async () => {
  const a = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    const raw = Buffer.from("img");
    const h = sha(raw);
    mkdirSync(a.blobs, { recursive: true });
    writeFileSync(join(a.blobs, h), raw);
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, `blob:sha256:${h}`);
    store.failOnPut.add(`t/blobs/${h}`);
    const r = await pushSync({ agentDir: a.dir, cfg, store });
    expect(r.pushed).toBe(1); // the session object did land (idempotent, retried next time)
    expect(r.errors.length).toBe(1);
    expect(store.keys()).not.toContain("t/manifest.json");
    expect(loadLocalState(a.dir).lastSynced).toEqual({});
  } finally {
    wipe(a);
  }
});

test("failed v1 push leaves v0 serving consistently (no wedge)", async () => {
  const a = makeAgent();
  const b = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    const raw = Buffer.from("img-v0");
    const h = sha(raw); // content-addressed blob name
    mkdirSync(a.blobs, { recursive: true });
    writeFileSync(join(a.blobs, h), raw);
    const abs = writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, `v0 blob:sha256:${h}`);
    expect((await pushSync({ agentDir: a.dir, cfg, store })).errors).toEqual([]);
    // Edit to v1 referencing a NEW blob, then fail that blob PUT: the v1
    // session object lands, but the manifest must stay on v0 and v0 must
    // keep serving cleanly (previous generation intact, no mismatch).
    const raw1 = Buffer.from("img-v1");
    const h1 = sha(raw1);
    writeFileSync(join(a.blobs, h1), raw1);
    appendFileSync(abs, `{"type":"message","id":"m2","parentId":"m1","timestamp":"2026-01-02T00:00:00.000Z","image":"blob:sha256:${h1}"}\n`);
    store.failOnPut.add(`t/blobs/${h1}`);
    const r = await pushSync({ agentDir: a.dir, cfg, store });
    expect(r.pushed).toBe(1);
    expect(r.errors.length).toBe(1);
    const m = await readManifest(store, "t/");
    const entry = m?.entries.find((e) => e.id === lid("f.jsonl"));
    if (!entry) throw new Error("entry missing");
    const v0obj = await store.getObject(entry.key);
    expect(v0obj).not.toBeNull();
    // A fresh machine pulls v0 with zero mismatch: manifest and object agree.
    const rp = await pullSync({ agentDir: b.dir, cfg, store });
    expect(rp.errors).toEqual([]);
    expect(rp.pulled).toBe(1);
    expect(sha(readFileSync(join(b.sessions, "-dev-x", "f.jsonl")))).toBe(entry.sha256);
  } finally {
    wipe(a);
    wipe(b);
  }
});

test("concurrent same-id pushes converge on existing objects", async () => {
  const a = makeAgent();
  const b = makeAgent();
  const c = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, "A-content");
    writeSession(b.sessions, "-dev-x", "f.jsonl", CWDA, "B-content");
    const [ra, rb] = await Promise.all([
      pushSync({ agentDir: a.dir, cfg, store }),
      pushSync({ agentDir: b.dir, cfg, store }),
    ]);
    expect(ra.errors).toEqual([]);
    expect(rb.errors).toEqual([]);
    const m = await readManifest(store, "t/");
    expect(m?.entries.length).toBe(1);
    const winner = m?.entries[0];
    if (!winner) throw new Error("entry missing");
    // Whichever generation won, its object exists with matching bytes:
    // pulls can never mismatch.
    const obj = await store.getObject(winner.key);
    expect(obj).not.toBeNull();
    expect(sha(open({ body: obj!.body }, KEY, Buffer.from(winner.key, "utf-8")))).toBe(winner.sha256);
    const rc = await pullSync({ agentDir: c.dir, cfg, store });
    expect(rc.errors).toEqual([]);
    expect(rc.pulled).toBe(1);
  } finally {
    wipe(a);
    wipe(b);
    wipe(c);
  }
});

test("pull restores into the managed sessions bucket with source mtime", async () => {
  const a = makeAgent();
  const b = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, "hello");
    await pushSync({ agentDir: a.dir, cfg, store });
    const r = await pullSync({ agentDir: b.dir, cfg, store });
    expect(r.errors).toEqual([]);
    expect(r.pulled).toBe(1);
    const bucket = bucketDirForCwd(CWDA, KO);
    const dest = join(b.sessions, bucket, "f.jsonl");
    expect(readFileSync(dest, "utf-8")).toContain('"hello"');
    const m = await readManifest(store, "t/");
    const entry = m?.entries.find((e) => e.id === lid("f.jsonl"));
    if (!entry) throw new Error("pulled entry missing from manifest");
    expect(statSync(dest).mtimeMs).toBe(entry.mtime);
  } finally {
    wipe(a);
    wipe(b);
  }
});

test("pull rejects bytes that mismatch the manifest hash", async () => {
  const a = makeAgent();
  const b = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, "real");
    await pushSync({ agentDir: a.dir, cfg, store });
    const m0 = await readManifest(store, "t/");
    const victim = m0?.entries.find((e) => e.id === lid("f.jsonl"));
    if (!victim) throw new Error("entry missing");
    // Swap in validly-sealed bytes for *different* content under the victim key
    // (correct AAD, so GCM passes and the manifest-hash check must catch it).
    const evil = seal(Buffer.from("evil"), KEY, Buffer.from(victim.key, "utf-8")).body;
    store.objects.set(victim.key, { body: evil, etag: '"x"' });
    const r = await pullSync({ agentDir: b.dir, cfg, store });
    expect(r.pulled).toBe(0);
    expect(r.errors.length).toBe(1);
    expect(r.errors[0]).toMatch(/mismatch/);
    expect(readdirSync(b.sessions)).toEqual([]);
    expect(loadLocalState(b.dir).lastSynced).toEqual({});
  } finally {
    wipe(a);
    wipe(b);
  }
});

test("conflict preserves both sides and adopts local on next push", async () => {
  const a = makeAgent();
  const b = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, "v1-remote");
    await pushSync({ agentDir: a.dir, cfg, store });
    const id = lid("f.jsonl");
    // Machine B agreed on v0 long ago, then edited locally; remote moved to v1.
    const dest = writeSession(b.sessions, "-dev-x", "f.jsonl", CWDA, "v0-local-edit");
    markSynced(b.dir, [{ id, sha256: sha("something-older") }]);
    const r = await pullSync({ agentDir: b.dir, cfg, store });
    expect(r.errors).toEqual([]);
    expect(r.conflicts).toBe(1);
    expect(r.pulled).toBe(0);
    expect(readFileSync(dest, "utf-8")).toContain("v0-local-edit"); // local untouched
    const copies = readdirSync(join(b.sessions, "-dev-x")).filter((f) => f.includes(".conflict-"));
    expect(copies.length).toBe(1);
    expect(readFileSync(join(b.sessions, "-dev-x", copies[0]), "utf-8")).toContain("v1-remote");
    // Next push adopts the local side exactly once (no re-conflict).
    const r2 = await pushSync({ agentDir: b.dir, cfg, store });
    expect(r2.errors).toEqual([]);
    expect(r2.pushed).toBe(2); // local v0 + the conflict copy as a new session
    const m = await readManifest(store, "t/");
    expect(m?.entries.find((e) => e.id === id)?.sha256).toBe(sha(readFileSync(dest)));
  } finally {
    wipe(a);
    wipe(b);
  }
});

test("skipped and failed pulls leave the base untouched", async () => {
  const a = makeAgent();
  const b = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, "v1");
    await pushSync({ agentDir: a.dir, cfg, store });
    const m0 = await readManifest(store, "t/");
    const id = lid("f.jsonl");
    const dest = writeSession(b.sessions, "-dev-x", "f.jsonl", CWDA, "v0");
    markSynced(b.dir, [{ id, sha256: sha(readFileSync(dest)) }]);
    void m0;
    const before = loadLocalState(b.dir).lastSynced;
    // Skipped (open session): base must not move.
    const r = await pullSync({ agentDir: b.dir, cfg, store, skipAbsPaths: new Set([dest]) });
    expect(r.skipped).toBe(1);
    expect(r.pulled).toBe(0);
    expect(loadLocalState(b.dir).lastSynced).toEqual(before);
    // Failed GET: base must not move either.
    const entry = (await readManifest(store, "t/"))?.entries.find((e) => e.id === id);
    if (!entry) throw new Error("entry missing");
    store.failOnGet.add(entry.key);
    const r2 = await pullSync({ agentDir: b.dir, cfg, store });
    expect(r2.errors.length).toBe(1);
    expect(loadLocalState(b.dir).lastSynced).toEqual(before);
  } finally {
    wipe(a);
    wipe(b);
  }
});

test("orphan HEAD errors keep the entry", async () => {
  const a = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    const idR = lid("old.jsonl");
    const keyR = `t/sessions/${CANON_A}/rr`;
    await store.putObject(keyR, Buffer.from("old-bytes"));
    await saveRemoteManifest(
      store,
      "t/",
      { version: 1, updatedAt: 1, entries: [{ id: idR, key: keyR, sha256: "3".repeat(64), size: 1, mtime: 1, cwd: CWDA, canonical: CANON_A }] },
      KEY,
    );
    store.failOnHead.add(keyR);
    writeSession(a.sessions, "-dev-x", "new.jsonl", CWDA, "new");
    const r = await pushSync({ agentDir: a.dir, cfg, store });
    expect(r.pushed).toBe(1);
    const m = await readManifest(store, "t/");
    expect(m?.entries.map((e) => e.id).sort()).toEqual([idR, lid("new.jsonl")].sort());
    expect(r.errors.some((e) => e.includes("orphan check"))).toBe(true);
  } finally {
    wipe(a);
  }
});

test("manifest CAS retry preserves disjoint fresh ids", async () => {
  const store = new FakeS3();
  const idY = lid("y.jsonl");
  const idX = lid("x.jsonl");
  const ent = (id: string, sha256: string, key?: string) => ({ id, key: key ?? `obj/${sha256}`, sha256, size: 1, mtime: 1, cwd: CWDA, canonical: CANON_A });
  // Winner's generation: Y already at v2.
  await saveRemoteManifest(store, "t/", { version: 1, updatedAt: 1, entries: [ent(idY, "b".repeat(64))] }, KEY);
  // Our stale view (built before the winner): Y still at v1, plus our new X.
  await saveRemoteManifest(
    store,
    "t/",
    { version: 1, updatedAt: 0, entries: [ent(idY, "a".repeat(64)), ent(idX, "4".repeat(64))] },
    KEY,
    '"stale-etag"',
    3,
    new Set([idX]),
  );
  const m = await readManifest(store, "t/");
  const byId = new Map(m?.entries.map((e) => [e.id, e.sha256]));
  expect(byId.get(idY)).toBe("b".repeat(64)); // winner's disjoint update survives
  expect(byId.get(idX)).toBe("4".repeat(64)); // our owned id lands
});

test("pull with unresolvable blobs writes nothing and records nothing", async () => {
  const a = makeAgent();
  const b = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    const raw = Buffer.from("img-bytes");
    const h = sha(raw); // content-addressed: filename MUST equal sha256(bytes)
    mkdirSync(a.blobs, { recursive: true });
    writeFileSync(join(a.blobs, h), raw);
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, `pic blob:sha256:${h}`);
    const p = await pushSync({ agentDir: a.dir, cfg, store });
    expect(p.errors).toEqual([]);
    // The blob object vanishes (manual bucket delete / partial state).
    store.objects.delete(`t/blobs/${h}`);
    const r = await pullSync({ agentDir: b.dir, cfg, store });
    expect(r.pulled).toBe(0);
    expect(r.errors.length).toBeGreaterThan(0);
    expect(readdirSync(b.sessions)).toEqual([]);
    expect(loadLocalState(b.dir).lastSynced).toEqual({});
    // Blob restored via the explicit repair path -> the same pull converges.
    const repair = await syncBlobs(a.dir, cfg, store);
    expect(repair.errors).toEqual([]);
    expect(repair.blobsPushed).toBe(1);
    const r2 = await pullSync({ agentDir: b.dir, cfg, store });
    expect(r2.errors).toEqual([]);
    expect(r2.pulled).toBe(1);
  } finally {
    wipe(a);
    wipe(b);
  }
});

test("concurrent first pushes merge instead of clobbering", async () => {
  const a = makeAgent();
  const b = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    writeSession(a.sessions, "-dev-x", "a.jsonl", CWDA, "A");
    writeSession(b.sessions, "-dev-x", "b.jsonl", CWDA, "B");
    const [ra, rb] = await Promise.all([
      pushSync({ agentDir: a.dir, cfg, store }),
      pushSync({ agentDir: b.dir, cfg, store }),
    ]);
    expect(ra.errors).toEqual([]);
    expect(rb.errors).toEqual([]);
    const m = await readManifest(store, "t/");
    expect(m?.entries.length).toBe(2);
  } finally {
    wipe(a);
    wipe(b);
  }
});
test("manifest moved between prefixes is rejected (AAD)", async () => {
  const store = new FakeS3();
  await saveRemoteManifest(store, "t/", { version: 1, updatedAt: 1, entries: [] }, KEY);
  const obj = await store.getObject("t/manifest.json");
  if (!obj) throw new Error("manifest missing");
  await store.putObject("o/manifest.json", obj.body);
  await expect(loadRemoteManifest(store, "o/", KEY)).rejects.toThrow();
  // ...while the home prefix still opens.
  expect(await loadRemoteManifest(store, "t/", KEY)).not.toBeNull();
});

test("manifest load performs no HEAD (single-generation GET)", async () => {
  const a = makeAgent();
  try {
    const store = new FakeS3();
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, "x");
    await pushSync({ agentDir: a.dir, cfg: makeCfg(), store });
    store.heads = 0;
    await loadRemoteManifest(store, "t/", KEY);
    expect(store.heads).toBe(0);
  } finally {
    wipe(a);
  }
});

test("pull refuses a symlinked bucket dir", async () => {
  const a = makeAgent();
  const b = makeAgent();
  try {
    const cfg = makeCfg();
    const store = new FakeS3();
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, "secret");
    await pushSync({ agentDir: a.dir, cfg, store });
    // Plant a bucket symlink escaping the managed root.
    const outside = join(b.dir, "outside");
    mkdirSync(outside, { recursive: true });
    const link = join(b.sessions, "-dev-x");
    symlinkSync(outside, link);
    const r = await pullSync({ agentDir: b.dir, cfg, store });
    expect(r.pulled).toBe(0);
    expect(r.errors.some((e) => e.includes("symlink"))).toBe(true);
    expect(readdirSync(outside)).toEqual([]);
  } finally {
    wipe(a);
    wipe(b);
  }
});

test("snapshotIdentity pins scan-vs-upload drift", () => {
  const v0 = Buffer.from(`{"type":"session","cwd":${JSON.stringify(CWDA)}}\nrest\n`);
  expect(snapshotIdentity(v0, CWDA)).toBeNull();
  expect(snapshotIdentity(v0, null)).not.toBeNull();
  const moved = Buffer.from('{"type":"session","cwd":"/elsewhere"}\nrest\n');
  expect(snapshotIdentity(moved, CWDA)).toMatch(/header changed/);
  expect(snapshotIdentity(moved, null)).toMatch(/header changed/);
  expect(snapshotIdentity(Buffer.from("garbage\n"), null)).toBeNull();
});

test("revalidateLocal matrix", () => {
  const dir = mkdtempSync(join(tmpdir(), "omp-sync-reval-"));
  try {
    const abs = join(dir, "f.jsonl");
    // Absent everywhere: safe.
    expect(revalidateLocal(abs, new Map())).toBeNull();
    writeFileSync(abs, "data");
    const st = statSync(abs);
    const scanned = new Map([[abs, { absPath: abs, filename: "f.jsonl", sha256: "s", size: st.size, mtime: st.mtimeMs, headerCwd: null, id: "i", canonical: "c" }]]);
    // Present and unchanged: safe.
    expect(revalidateLocal(abs, scanned)).toBeNull();
    // Present but unseen at scan: refuse.
    expect(revalidateLocal(abs, new Map())).toMatch(/changed/);
    // Changed since scan: refuse.
    appendFileSync(abs, "more");
    expect(revalidateLocal(abs, scanned)).toMatch(/changed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("oversized blob warns but never blocks the manifest", async () => {
  const a = makeAgent();
  try {
    const cfg = makeCfg({ maxBlobBytes: 16 });
    const store = new FakeS3();
    const raw = Buffer.from("this-blob-is-definitely-over-sixteen-bytes");
    const h = sha(raw);
    mkdirSync(a.blobs, { recursive: true });
    writeFileSync(join(a.blobs, h), raw);
    writeSession(a.sessions, "-dev-x", "f.jsonl", CWDA, `pic blob:sha256:${h}`);
    const r = await pushSync({ agentDir: a.dir, cfg, store });
    // Session publishes; the blob becomes a warning, not an error.
    expect(r.errors).toEqual([]);
    expect(r.pushed).toBe(1);
    expect(r.warnings.some((w) => w.includes("exceeds maxBlobBytes"))).toBe(true);
    expect(store.keys()).toContain("t/manifest.json");
    expect(store.keys()).not.toContain(`t/blobs/${h}`);
    expect(loadLocalState(a.dir).lastSynced[lid("f.jsonl")]).toBeDefined();
    // And the second push does not wedge: clean no-op (the unchanged
    // session no longer re-walks the blob).
    const r2 = await pushSync({ agentDir: a.dir, cfg, store });
    expect(r2.errors).toEqual([]);
    expect(r2.pushed).toBe(0);
    // Raising the cap and touching nothing else still uploads the blob
    // through the explicit blobs command — the escape hatch works.
    const repair = await syncBlobs(a.dir, makeCfg(), store);
    expect(repair.errors).toEqual([]);
    expect(repair.blobsPushed).toBe(1);
  } finally {
    wipe(a);
  }
});

test("sessionsRoot follows omp's XDG redirection", () => {
  const saved = process.env.XDG_DATA_HOME;
  const xdg = mkdtempSync(join(tmpdir(), "xdg-"));
  try {
    // No XDG: default agent tree.
    delete process.env.XDG_DATA_HOME;
    expect(agentPaths("/tmp/agent").sessionsRoot).toBe(join("/tmp/agent", "sessions"));
    // XDG set but omp's dir absent: still the default.
    process.env.XDG_DATA_HOME = xdg;
    expect(agentPaths("/tmp/agent").sessionsRoot).toBe(join("/tmp/agent", "sessions"));
    // XDG set and $XDG_DATA_HOME/omp exists: redirected root.
    mkdirSync(join(xdg, "omp", "sessions"), { recursive: true });
    expect(agentPaths("/tmp/agent").sessionsRoot).toBe(join(xdg, "omp", "sessions"));
  } finally {
    if (saved === undefined) delete process.env.XDG_DATA_HOME;
    else process.env.XDG_DATA_HOME = saved;
    rmSync(xdg, { recursive: true, force: true });
  }
});

test("malformed manifest entries are refused at load", async () => {
  const store = new FakeS3();
  const mk = (entries: unknown[]): Buffer =>
    seal(Buffer.from(JSON.stringify({ version: 1, updatedAt: 1, entries })), KEY, Buffer.from("t/manifest.json", "utf-8")).body;
  const put = async (entries: unknown[]): Promise<void> => {
    await store.putObject("t/manifest.json", mk(entries));
  };
  await put([{ id: "sessions/x/a.jsonl", key: "k", sha256: "nothex", size: 1, mtime: 1, cwd: null, canonical: "c" }]);
  await expect(loadRemoteManifest(store, "t/", KEY)).rejects.toThrow(/invalid shape/);
  await put([{ id: "not-sessions/a", key: "k", sha256: "a".repeat(64), size: 1, mtime: 1, cwd: null, canonical: "c" }]);
  await expect(loadRemoteManifest(store, "t/", KEY)).rejects.toThrow(/invalid shape/);
  await put([{ id: "sessions/x/a.jsonl", key: "k", sha256: "a".repeat(64), size: 1, mtime: NaN, cwd: null, canonical: "c" }]);
  await expect(loadRemoteManifest(store, "t/", KEY)).rejects.toThrow(/invalid shape/);
  // Well-formed still loads.
  await put([{ id: "sessions/x/a.jsonl", key: "k", sha256: "a".repeat(64), size: 1, mtime: 1, cwd: "/h", canonical: "c" }]);
  const ok = await loadRemoteManifest(store, "t/", KEY);
  expect(ok?.manifest.entries.length).toBe(1);
});
