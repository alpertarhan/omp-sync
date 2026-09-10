import { test, expect } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, openSync, writeSync, closeSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyPathMap,
  blobObjectKey,
  blobRefsIn,
  bucketDirForCwd,
  canonicalProjectKey,
  readSessionHeader,
  sessionLogicalId,
  sessionObjectKey,
} from "../src/keys.js";

const HOME = "/Users/alper";
const TMP = "/private/tmp";
const o = { home: HOME, tmpdir: TMP } as const;

test("home-relative cwd is portable", () => {
  expect(canonicalProjectKey("/Users/alper/dev/bengu", o)).toBe("home/dev/bengu");
});

test("home itself maps to bare home", () => {
  expect(canonicalProjectKey("/Users/alper", o)).toBe("home");
});

test("tmpdir cwd stays host-shaped", () => {
  expect(canonicalProjectKey("/private/tmp/foo", o)).toBe("tmp/foo");
});

test("outside paths are absolute-encoded", () => {
  expect(canonicalProjectKey("/data/proj", o)).toBe("abs/data/proj");
});

test("foreign home shapes converge across mac/linux", () => {
  const mac = { home: "/Users/ersin", tmpdir: "/private/tmp" };
  const lin = { home: "/home/ersin", tmpdir: "/tmp" };
  // A mac-born session rescanned on linux and vice versa: same key, no pathMap.
  expect(canonicalProjectKey("/Users/ersin/Projects/acme", lin)).toBe("home/Projects/acme");
  expect(canonicalProjectKey("/home/ersin/Projects/acme", mac)).toBe("home/Projects/acme");
  // Usernames are irrelevant; foreign home roots map to bare home; /root too.
  expect(canonicalProjectKey("/home/someone-else/x", mac)).toBe("home/x");
  expect(canonicalProjectKey("/Users/ersin", lin)).toBe("home");
  expect(canonicalProjectKey("/root/x", lin)).toBe("home/x");
});

test("home-shaped non-home paths stay absolute", () => {
  expect(canonicalProjectKey("/homebrew/x", o)).toBe("abs/homebrew/x");
  expect(canonicalProjectKey("/homex/y", o)).toBe("abs/homex/y");
});

test("logical id survives the mac/linux round trip", () => {
  const mac = { home: "/Users/ersin", tmpdir: "/private/tmp" };
  const lin = { home: "/home/ersin", tmpdir: "/tmp" };
  // Regression: a pulled file keeps its foreign header cwd, so the rescan
  // used to diverge to abs/... and push/pull-loop the same session forever.
  const pushed = sessionLogicalId(canonicalProjectKey("/Users/ersin/Projects/acme", mac), "x.jsonl");
  const rescanned = sessionLogicalId(canonicalProjectKey("/Users/ersin/Projects/acme", lin), "x.jsonl");
  expect(rescanned).toBe(pushed);
});

test("pathMap normalizes foreign cwds into the local vocabulary", () => {
  // A mac-authored cwd arriving on a linux box with a different home:
  // the map folds it under the local home so both sides converge.
  const lin = { home: "/home/alper", tmpdir: "/tmp", pathMap: [{ from: "/Users/alper/", to: "/home/alper/" }] };
  expect(canonicalProjectKey("/Users/alper/dev/bengu", lin)).toBe("home/dev/bengu");
  // And the local machine needs no map for its own tree.
  expect(canonicalProjectKey("/Users/alper/dev/bengu", o)).toBe("home/dev/bengu");
});

test("pathMap longest prefix wins", () => {
  const opts = {
    ...o,
    pathMap: [
      { from: "/Users/", to: "/home/" },
      { from: "/Users/alper/work/", to: "/srv/work/" },
    ],
  };
  expect(canonicalProjectKey("/Users/alper/work/x", opts)).toBe("abs/srv/work/x");
});

test("bucket dir mirrors omp encoding (home-relative)", () => {
  const opts = { ...o, canonicalize: false };
  expect(bucketDirForCwd("/Users/alper/dev/bengu", opts)).toBe("-dev-bengu");
  expect(bucketDirForCwd("/Users/alper", opts)).toBe("-");
});

test("bucket dir mirrors omp encoding (tmp + absolute)", () => {
  const opts = { ...o, canonicalize: false };
  expect(bucketDirForCwd("/private/tmp/foo", opts)).toBe("-tmp-foo");
  expect(bucketDirForCwd("/data/proj", opts)).toBe("--data-proj--");
});

test("bucket dir honors pathMap before encoding", () => {
  const lin = { home: "/home/alper", tmpdir: "/tmp", pathMap: [{ from: "/Users/alper/", to: "/home/alper/" }], canonicalize: false };
  expect(bucketDirForCwd("/Users/alper/dev/bengu", lin)).toBe("-dev-bengu");
});

test("bucket dir folds a foreign home cwd into the native bucket", () => {
  const lin = { home: "/home/ersin", tmpdir: "/tmp", canonicalize: false };
  expect(bucketDirForCwd("/Users/ersin/Projects/acme", lin)).toBe("-Projects-acme");
  const mac = { home: "/Users/ersin", tmpdir: "/private/tmp", canonicalize: false };
  expect(bucketDirForCwd("/home/ersin/Projects/acme", mac)).toBe("-Projects-acme");
  expect(bucketDirForCwd("/root/x", mac)).toBe("-x");
});

test("logical ids are stable, object keys are content-addressed", () => {
  expect(sessionLogicalId("home/dev/bengu", "a.jsonl")).toBe("sessions/home/dev/bengu/a.jsonl");
  expect(() => sessionLogicalId("home/x", "../evil.jsonl")).toThrow(/unsafe/);
  const h = "a".repeat(64);
  expect(sessionObjectKey("omp-sync/", "home/dev/bengu", h)).toBe(`omp-sync/sessions/home/dev/bengu/${h}.enc`);
  expect(() => sessionObjectKey("omp-sync/", "home/x", "nope")).toThrow();
});
test("blob keys require hex hashes", () => {
  const h = "a".repeat(64);
  expect(blobObjectKey("omp-sync/", h)).toBe(`omp-sync/blobs/${h}`);
  expect(() => blobObjectKey("omp-sync/", "nope")).toThrow();
});

test("header reader handles slot-less files", () => {
  const dir = mkdtempSync(join(tmpdir(), "omp-sync-"));
  try {
    const f = join(dir, "s.jsonl");
    writeFileSync(f, `{"type":"session","version":3,"id":"x","cwd":"/Users/alper/dev/b"}\n{"type":"message"}\n`);
    expect(readSessionHeader(f)).toEqual({ cwd: "/Users/alper/dev/b" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("header reader skips the omp title slot", () => {
  const dir = mkdtempSync(join(tmpdir(), "omp-sync-"));
  try {
    const f = join(dir, "s.jsonl");
    writeFileSync(
      f,
      `{"type":"title","title":"hi"}\n{"type":"session","version":3,"id":"x","cwd":"/tmp"}\n{"type":"message"}\n`,
    );
    expect(readSessionHeader(f)).toEqual({ cwd: "/tmp" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("header reader returns null cwd on garbage", () => {
  const dir = mkdtempSync(join(tmpdir(), "omp-sync-"));
  try {
    const f = join(dir, "s.jsonl");
    mkdirSync(join(dir, "sub"));
    writeFileSync(f, "not json\n");
    expect(readSessionHeader(f)).toEqual({ cwd: null });
    expect(readSessionHeader(join(dir, "missing.jsonl"))).toEqual({ cwd: null });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
test("header reader uses a bounded prefix on huge files", () => {
  const dir = mkdtempSync(join(tmpdir(), "omp-sync-"));
  try {
    const f = join(dir, "big.jsonl");
    const fd = openSync(f, "w");
    writeSync(fd, `{"type":"session","version":3,"id":"big","cwd":"/home/u/proj"}\n`);
    const chunk = Buffer.alloc(1024 * 1024, "x");
    for (let i = 0; i < 20; i++) writeSync(fd, chunk); // 20 MiB of transcript
    closeSync(fd);
    expect(statSync(f).size).toBeGreaterThan(20 * 1024 * 1024);
    expect(readSessionHeader(f)).toEqual({ cwd: "/home/u/proj" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("blob refs are extracted and deduped", () => {
  const h1 = "b".repeat(64);
  const h2 = "c".repeat(64);
  const refs = blobRefsIn(`img blob:sha256:${h1} again blob:sha256:${h1} other blob:sha256:${h2} short blob:sha256:xyz`);
  expect(refs.sort()).toEqual([h1, h2].sort());
});
