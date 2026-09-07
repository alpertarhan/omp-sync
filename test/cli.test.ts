/**
 * Extension-host contract tests with a mocked ExtensionAPI: the factory must
 * do nothing but register (install-time validation runs it against a
 * throwaway surface), and doctor/unlock work without a usable sync config.
 */
import { test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import ompSyncExtension from "../extensions/omp-sync.js";

interface Ctx {
  hasUI: boolean;
  ui: { notify: (msg: string, level?: string) => void };
  sessionManager: Record<string, never>;
}

function mockPi() {
  const commands = new Map<string, { description?: string; handler: (args: string, ctx: Ctx) => Promise<void> }>();
  const events = new Map<string, ((...a: unknown[]) => unknown)[]>();
  return {
    api: {
      registerCommand: (name: string, opts: { description?: string; handler: (args: string, ctx: Ctx) => Promise<void> }) => {
        commands.set(name, opts);
      },
      on: (ev: string, h: (...a: unknown[]) => unknown) => {
        events.set(ev, [...(events.get(ev) ?? []), h]);
      },
    },
    commands,
    events,
  };
}

function mockCtx(notify: (msg: string) => void, hasUI = true): Ctx {
  return { hasUI, ui: { notify }, sessionManager: {} };
}

const savedEnv = { ...process.env };
beforeEach(() => {
  for (const k of Object.keys(process.env)) {
    if (k.startsWith("OMP_SYNC_") || k === "PI_CODING_AGENT_DIR") delete process.env[k];
  }
});
afterEach(() => {
  for (const k of Object.keys(process.env)) {
    if (k.startsWith("OMP_SYNC_") || k === "PI_CODING_AGENT_DIR") delete process.env[k];
  }
  Object.assign(process.env, savedEnv);
});

test("factory only registers, never touches the network or disk", () => {
  const { api, commands, events } = mockPi();
  ompSyncExtension(api as never);
  expect([...commands.keys()]).toEqual(["omp-sync"]);
  expect([...events.keys()].sort()).toEqual(["session_shutdown", "session_start", "turn_end"]);
});

test("doctor works without any config", async () => {
  const agentDir = mkdtempSync(join(tmpdir(), "omp-sync-cli-"));
  try {
    process.env.PI_CODING_AGENT_DIR = agentDir;
    const { api, commands } = mockPi();
    ompSyncExtension(api as never);
    const seen: string[] = [];
    await commands.get("omp-sync")?.handler("doctor", mockCtx((m) => seen.push(m)));
    const out = seen.join("\n");
    expect(out).toContain("config:      MISSING");
    expect(out).toContain(`agentDir:    ${agentDir}`);
  } finally {
    rmSync(agentDir, { recursive: true, force: true });
  }
});

test("status without config reports No config", async () => {
  const agentDir = mkdtempSync(join(tmpdir(), "omp-sync-cli-"));
  try {
    process.env.PI_CODING_AGENT_DIR = agentDir;
    const { api, commands } = mockPi();
    ompSyncExtension(api as never);
    const seen: string[] = [];
    await commands.get("omp-sync")?.handler("status", mockCtx((m) => seen.push(m)));
    expect(seen.join("\n")).toContain("No config");
  } finally {
    rmSync(agentDir, { recursive: true, force: true });
  }
});

test("unlock clears a stale lock without config", async () => {
  const agentDir = mkdtempSync(join(tmpdir(), "omp-sync-cli-"));
  try {
    process.env.PI_CODING_AGENT_DIR = agentDir;
    mkdirSync(join(agentDir, ".omp-sync"), { recursive: true });
    writeFileSync(
      join(agentDir, ".omp-sync", "lock"),
      JSON.stringify({ id: "x", pid: 1, command: "push", startedAt: new Date(Date.now() - 3600_000).toISOString() }),
    );
    const { api, commands } = mockPi();
    ompSyncExtension(api as never);
    const seen: string[] = [];
    await commands.get("omp-sync")?.handler("unlock", mockCtx((m) => seen.push(m)));
    expect(seen.join("\n")).toContain("removed lock");
    expect(existsSync(join(agentDir, ".omp-sync", "lock"))).toBe(false);
  } finally {
    rmSync(agentDir, { recursive: true, force: true });
  }
});

test("unknown subcommand lists usage", async () => {
  const agentDir = mkdtempSync(join(tmpdir(), "omp-sync-cli-"));
  try {
    process.env.PI_CODING_AGENT_DIR = agentDir;
    const { api, commands } = mockPi();
    ompSyncExtension(api as never);
    const seen: string[] = [];
    await commands.get("omp-sync")?.handler("bogus", mockCtx((m) => seen.push(m)));
    expect(seen.join("\n")).toContain("unknown 'bogus'");
  } finally {
    rmSync(agentDir, { recursive: true, force: true });
  }
});
test("doctor works with a null-JSON config file", async () => {
  const agentDir = mkdtempSync(join(tmpdir(), "omp-sync-cli-"));
  try {
    process.env.PI_CODING_AGENT_DIR = agentDir;
    writeFileSync(join(agentDir, "omp-sync.local.json"), "null");
    const { api, commands } = mockPi();
    ompSyncExtension(api as never);
    const seen: string[] = [];
    await commands.get("omp-sync")?.handler("doctor", mockCtx((m) => seen.push(m)));
    expect(seen.join("\n")).toContain("config:      MISSING");
  } finally {
    rmSync(agentDir, { recursive: true, force: true });
  }
});

test("unlock removes an unreadable lock file", async () => {
  const agentDir = mkdtempSync(join(tmpdir(), "omp-sync-cli-"));
  try {
    process.env.PI_CODING_AGENT_DIR = agentDir;
    mkdirSync(join(agentDir, ".omp-sync"), { recursive: true });
    writeFileSync(join(agentDir, ".omp-sync", "lock"), "{truncated");
    const { api, commands } = mockPi();
    ompSyncExtension(api as never);
    const seen: string[] = [];
    await commands.get("omp-sync")?.handler("unlock", mockCtx((m) => seen.push(m)));
    expect(seen.join("\n")).toContain("removed unreadable lock file");
    expect(existsSync(join(agentDir, ".omp-sync", "lock"))).toBe(false);
  } finally {
    rmSync(agentDir, { recursive: true, force: true });
  }
});

test("background lifecycle paths never create a lock file", async () => {
  const agentDir = mkdtempSync(join(tmpdir(), "omp-sync-cli-"));
  const realFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = (async () => {
    fetchCalls++;
    throw new Error("refused");
  }) as unknown as typeof fetch;
  try {
    process.env.PI_CODING_AGENT_DIR = agentDir;
    process.env.OMP_SYNC_ENDPOINT = "https://127.0.0.1:9";
    process.env.OMP_SYNC_BUCKET = "bkt";
    process.env.OMP_SYNC_ACCESS_KEY_ID = "a";
    process.env.OMP_SYNC_SECRET_ACCESS_KEY = "s";
    process.env.OMP_SYNC_AUTO_PULL = "1";
    process.env.OMP_SYNC_ENCRYPTION_KEY = Buffer.from(new Uint8Array(32).fill(7)).toString("base64");
    const { api, events } = mockPi();
    ompSyncExtension(api as never);
    const timers: { fn: () => void }[] = [];
    const sessionFile = join(agentDir, "sessions", "-dev-x", "open.jsonl");
    mkdirSync(join(agentDir, "sessions", "-dev-x"), { recursive: true });
    writeFileSync(sessionFile, '{"type":"session","cwd":"/x"}\n');
    const ctx = {
      hasUI: true,
      ui: { notify: () => {} },
      sessionManager: { getSessionFile: () => sessionFile },
      setTimeout: (fn: () => void) => {
        timers.push({ fn });
        return timers.length;
      },
      clearTimer: () => {},
    };
    for (const h of events.get("turn_end") ?? []) await h({}, ctx);
    for (const t of timers) t.fn(); // fire debounced auto-push (fails fast: stubbed fetch)
    for (const h of events.get("session_start") ?? []) await h({}, ctx);
    for (const h of events.get("session_shutdown") ?? []) await h({}, ctx);
    // Wait for the observed signal (background network attempts), not a guess:
    // turn_end push alone issues manifest GET + session PUT.
    const deadline = Date.now() + 2000;
    while (fetchCalls < 2 && Date.now() < deadline) await Bun.sleep(10);
    expect(fetchCalls).toBeGreaterThanOrEqual(2); // background work actually ran
    expect(existsSync(join(agentDir, ".omp-sync", "lock"))).toBe(false);
  } finally {
    globalThis.fetch = realFetch;
    rmSync(agentDir, { recursive: true, force: true });
  }
});
test("headless mode logs to stdout instead of notifying", async () => {
  const agentDir = mkdtempSync(join(tmpdir(), "omp-sync-cli-"));
  const realLog = console.log;
  const logged: string[] = [];
  console.log = (msg: unknown) => {
    logged.push(String(msg));
  };
  try {
    process.env.PI_CODING_AGENT_DIR = agentDir;
    const { api, commands } = mockPi();
    ompSyncExtension(api as never);
    const seen: string[] = [];
    // hasUI false: notify must NOT fire, stdout must carry the output.
    await commands.get("omp-sync")?.handler("doctor", { hasUI: false, ui: { notify: (m: string) => seen.push(m) }, sessionManager: {} });
    expect(seen).toEqual([]);
    expect(logged.join("\n")).toContain("config:      MISSING");
  } finally {
    console.log = realLog;
    rmSync(agentDir, { recursive: true, force: true });
  }
});
