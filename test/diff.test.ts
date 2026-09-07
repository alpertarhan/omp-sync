import { test, expect } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  diffWithBase,
  isStaleLock,
  loadLocalState,
  markSynced,
  scanLocalSessions,
  withLock,
  LockHeldError,
  type LocalFile,
  type ManifestEntry,
} from "../src/store.js";

function file(over: Partial<LocalFile> & { id: string }): LocalFile {
  return {
    absPath: `/x/${over.id}`,
    filename: "f.jsonl",
    sha256: "s",
    size: 1,
    mtime: 100,
    headerCwd: null,
    canonical: "home/x",
    ...over,
  };
}

function entry(id: string, sha256: string, key?: string): ManifestEntry {
  return { id, key: key ?? `obj/${sha256}`, sha256, size: 1, mtime: 1, cwd: null, canonical: "c" };
}

test("new local file pushes, remote-only pulls", () => {
  const d = diffWithBase([file({ id: "k/a", sha256: "a" })], { version: 1, updatedAt: 0, entries: [entry("k/b", "b")] }, {});
  expect(d.toPush.map((f) => f.id)).toEqual(["k/a"]);
  expect(d.toPull.map((f) => f.id)).toEqual(["k/b"]);
  expect(d.upToDate).toBe(0);
});

test("same sha is up to date", () => {
  const d = diffWithBase([file({ id: "k", sha256: "s" })], { version: 1, updatedAt: 0, entries: [entry("k", "s")] }, { k: "s" });
  expect(d.upToDate).toBe(1);
});

test("matching ignores object keys: same id+sha with rotated keys is current", () => {
  // Content-addressed generations: the object key changed but the bytes agree.
  const d = diffWithBase([file({ id: "k", sha256: "s" })], { version: 1, updatedAt: 0, entries: [entry("k", "s", "obj/other-gen")] }, {});
  expect(d.upToDate).toBe(1);
  expect(d.toPush).toEqual([]);
  expect(d.toPull).toEqual([]);
});

test("base decides direction: remote moved -> pull", () => {
  const d = diffWithBase([file({ id: "k", sha256: "local" })], { version: 1, updatedAt: 0, entries: [entry("k", "remote")] }, { k: "local" });
  expect(d.toPull.map((f) => f.id)).toEqual(["k"]);
  expect(d.toPush).toEqual([]);
});

test("base decides direction: local moved -> push", () => {
  const d = diffWithBase([file({ id: "k", sha256: "local" })], { version: 1, updatedAt: 0, entries: [entry("k", "remote")] }, { k: "remote" });
  expect(d.toPush.map((f) => f.id)).toEqual(["k"]);
  expect(d.toPull).toEqual([]);
});

test("diverged both sides -> conflict, nothing silently won", () => {
  const d = diffWithBase([file({ id: "k", sha256: "local" })], { version: 1, updatedAt: 0, entries: [entry("k", "remote")] }, { k: "base" });
  expect(d.conflicts.map((c) => c.local.id)).toEqual(["k"]);
  expect(d.toPush).toEqual([]);
  expect(d.toPull).toEqual([]);
});

test("first contact falls back to mtime, ties push", () => {
  const mk = (mtime: number, sha: string) => file({ id: "k", sha256: sha, mtime });
  const rmt = (mtime: number) => ({ ...entry("k", "r"), mtime });
  const tie = diffWithBase([mk(100, "l")], { version: 1, updatedAt: 0, entries: [rmt(100)] }, {});
  expect(tie.toPush.length).toBe(1);
  const older = diffWithBase([mk(50, "l")], { version: 1, updatedAt: 0, entries: [rmt(100)] }, {});
  expect(older.toPull.length).toBe(1);
});

test("disjoint marks merge without read-modify-write", () => {
  const dir = mkdtempSync(join(tmpdir(), "omp-sync-"));
  try {
    expect(loadLocalState(dir).lastSynced).toEqual({});
    markSynced(dir, [{ id: "a", sha256: "1" }]);
    markSynced(dir, [{ id: "b", sha256: "2" }]);
    // A later mark for one id never disturbs the other: each record is an
    // independent atomic file, so concurrent disjoint writers cannot lose
    // each other's updates.
    markSynced(dir, [{ id: "a", sha256: "3" }]);
    expect(loadLocalState(dir).lastSynced).toEqual({ a: "3", b: "2" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("legacy v2 snapshot migrates to per-key records once", () => {
  const dir = mkdtempSync(join(tmpdir(), "omp-sync-"));
  try {
    mkdirSync(join(dir, ".omp-sync"), { recursive: true });
    writeFileSync(join(dir, ".omp-sync", "state.json"), JSON.stringify({ version: 2, lastSynced: { k: "s" } }));
    expect(loadLocalState(dir).lastSynced).toEqual({ k: "s" });
    expect(existsSync(join(dir, ".omp-sync", "state.json"))).toBe(false);
    expect(loadLocalState(dir).lastSynced).toEqual({ k: "s" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("legacy v1 state is ignored", () => {
  const dir = mkdtempSync(join(tmpdir(), "omp-sync-"));
  try {
    mkdirSync(join(dir, ".omp-sync"), { recursive: true });
    writeFileSync(join(dir, ".omp-sync", "state.json"), JSON.stringify({ version: 1, lastSynced: { k: "s" } }));
    expect(loadLocalState(dir).lastSynced).toEqual({});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("lock is exclusive and self-cleaning", async () => {
  const dir = mkdtempSync(join(tmpdir(), "omp-sync-"));
  try {
    const order: string[] = [];
    await withLock(dir, "a", async () => {
      order.push("in");
      await expect(withLock(dir, "b", async () => {})).rejects.toBeInstanceOf(LockHeldError);
    });
    order.push("out");
    expect(order).toEqual(["in", "out"]);
    // released: acquirable again
    await withLock(dir, "c", async () => {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("unreadable lock counts as stale", () => {
  expect(isStaleLock(undefined)).toBe(true);
  expect(isStaleLock({ id: "x", pid: -1, command: "c", startedAt: new Date().toISOString() })).toBe(true);
  expect(isStaleLock({ id: "x", pid: process.pid, command: "c", startedAt: new Date().toISOString() })).toBe(false);
});

test("scan picks jsonl files, skips dirs and sidecars", async () => {
  const root = mkdtempSync(join(tmpdir(), "omp-sync-"));
  try {
    const bucket = join(root, "-dev-x");
    mkdirSync(bucket, { recursive: true });
    writeFileSync(join(bucket, "a.jsonl"), `{"type":"session","cwd":"/home/u/dev/x"}\n`);
    mkdirSync(join(bucket, "a.jsonl.sidecar"));
    writeFileSync(join(bucket, "notes.txt"), "hi");
    const files = await scanLocalSessions(root, (filename, cwd) => ({
      id: `p/${cwd ?? "?"}/${filename}`,
      canonical: "c",
    }));
    expect(files.map((f) => f.filename)).toEqual(["a.jsonl"]);
    expect(files[0].headerCwd).toBe("/home/u/dev/x");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("scan on missing root returns empty", async () => {
  expect(await scanLocalSessions(join(tmpdir(), "omp-sync-nope"), () => ({ id: "k", canonical: "c" }))).toEqual([]);
});
