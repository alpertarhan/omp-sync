/**
 * omp-sync extension entry.
 *
 * Registers the `omp-sync` command (status/push/pull/blobs/doctor/config/unlock)
 * and wires lifecycle automation:
 * - turn_end (debounced): push just the current session file — small uploads
 *   spread across the work instead of one big push at exit.
 * - session_start (opt-in): pull everything except the open session file.
 * - session_shutdown: best-effort push of the current file only. omp caps
 *   shutdown handlers at ~2s, so no full sync happens here by design.
 */
import type { ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import {
  describeConfig,
  doctorSync,
  loadSyncConfig,
  pullSync,
  pushSync,
  resolveAgentDir,
  statusSync,
  syncBlobs,
  type SyncConfig,
  type SyncReport,
} from "../src/sync.js";
import { isStaleLock, lockPath, readLock, withLock, LockHeldError } from "../src/store.js";
import { existsSync, rmSync } from "node:fs";

const SUBCOMMANDS = ["status", "push", "pull", "blobs", "doctor", "config", "unlock"] as const;

function fmtReport(r: SyncReport): string {
  const parts = [`pushed ${r.pushed}`, `pulled ${r.pulled}`, `upToDate ${r.upToDate}`];
  if (r.conflicts) parts.push(`${r.conflicts} conflict${r.conflicts === 1 ? "" : "s"} (remote copies kept)`);
  if (r.blobsPushed || r.blobsPulled) parts.push(`blobs +${r.blobsPushed}/-${r.blobsPulled}`);
  if (r.skipped) parts.push(`skipped ${r.skipped}`);
  if (r.errors.length) parts.push(`${r.errors.length} error${r.errors.length === 1 ? "" : "s"}`);
  if (r.warnings.length) parts.push(`${r.warnings.length} warning${r.warnings.length === 1 ? "" : "s"}`);
  return parts.join(", ");
}
function reportLine(prefix: string, r: SyncReport): string {
  const lines = [`${prefix} — ${fmtReport(r)}`];
  for (const e of r.errors.slice(0, 5)) lines.push(`  ! ${e}`);
  if (r.errors.length > 5) lines.push(`  … +${r.errors.length - 5} more`);
  for (const w of r.warnings.slice(0, 3)) lines.push(`  ~ ${w}`);
  if (r.warnings.length > 3) lines.push(`  … +${r.warnings.length - 3} more warnings`);
  return lines.join("\n");
}

/**
 * Exactly one output surface, never both: a transient notification in TUI
 * (stdout writes would corrupt the fullscreen terminal), stdout only in
 * headless modes where notify is a no-op. No widgets, no overlays, no
 * persistent UI of any kind.
 */
function say(ctx: ExtensionContext, msg: string, level: "info" | "warning" | "error" = "info"): void {
  if (ctx.hasUI) {
    try {
      ctx.ui.notify(msg, level);
    } catch {
      /* a throwing UI must not fail the sync */
    }
    return;
  }
  console.log(msg);
}

/** Current open session file, when the host exposes it. */
function currentSessionFile(ctx: ExtensionContext): string | undefined {
  try {
    const sm = (ctx as ExtensionContext).sessionManager as
      | { getSessionFile?: () => string }
      | undefined;
    const f = sm?.getSessionFile?.();
    return typeof f === "string" && f ? f : undefined;
  } catch {
    return undefined;
  }
}

export default function ompSyncExtension(pi: ExtensionAPI): void {
  const host = { getAgentDir: () => (pi as unknown as { pi?: { getAgentDir?: () => string } }).pi?.getAgentDir?.() ?? "" };

  pi.registerCommand("omp-sync", {
    description: "Encrypted per-session sync (S3/R2). status/push/pull/blobs/doctor/config/unlock.",
    getArgumentCompletions(argumentPrefix: string) {
      if (argumentPrefix.includes(" ")) return null;
      const q = argumentPrefix.trim().toLowerCase();
      const items = SUBCOMMANDS.filter((s) => s.startsWith(q)).map((s) => ({ label: s, value: s }));
      return items.length ? items : null;
    },
    handler: async (rawArgs: string, ctx: ExtensionContext) => {
      const [sub = "status", ...rest] = rawArgs.trim().split(/\s+/).filter(Boolean);
      const agentDir = resolveAgentDir(host);
      // doctor/unlock/config must work precisely when the sync config is
      // broken or missing — that is when you need them. Only data commands
      // require a usable config.
      const cfg = loadSyncConfig(agentDir);
      const requireCfg = (): SyncConfig => {
        if (!cfg) throw new Error(`No config: create ${agentDir}/omp-sync.local.json or set OMP_SYNC_* env vars.`);
        return cfg;
      };
      try {
        if (sub === "status") {
          const c = requireCfg();
          const st = await withLock(agentDir, "status", () => statusSync(agentDir, c));
          say(
            ctx,
            `agentDir: ${st.agentDir}\nlocal: ${st.localCount} | remote: ${st.remoteCount ?? "?"}\ntoPush: ${st.toPush} | toPull: ${st.toPull} | conflicts: ${st.conflicts} | upToDate: ${st.upToDate}`,
          );
        } else if (sub === "push") {
          const c = requireCfg();
          const r = await withLock(agentDir, "push", () => pushSync({ agentDir, cfg: c }));
          say(ctx, reportLine("push done", r), r.errors.length ? "warning" : "info");
        } else if (sub === "pull") {
          const c = requireCfg();
          const current = currentSessionFile(ctx);
          const r = await withLock(agentDir, "pull", () =>
            pullSync({ agentDir, cfg: c, skipAbsPaths: current ? new Set([current]) : undefined }),
          );
          say(ctx, reportLine("pull done", r), r.errors.length ? "warning" : "info");
        } else if (sub === "blobs") {
          const c = requireCfg();
          const r = await withLock(agentDir, "blobs", () => syncBlobs(agentDir, c));
          say(ctx, reportLine("blobs done", r), r.errors.length ? "warning" : "info");
        } else if (sub === "doctor") {
          const d = await doctorSync(agentDir);
          const cur = readLock(agentDir);
          const lines = [
            `agentDir:    ${d.agentDir}`,
            `config:      ${d.configOk ? `ok (${d.configSource})` : "MISSING"}`,
            `encrypt key: ${d.keyOk ? "ok (32-byte)" : "MISSING"}`,
            `bucket:      ${d.pingOk ? "reachable" : "UNREACHABLE"}`,
            `local:       ${d.localCount} sessions`,
            `remote:      ${d.remoteCount} sessions${d.remoteManifest ? "" : " (no manifest yet)"}`,
            `prefix:      ${d.prefix}`,
            `lock:        ${cur ? `held by pid ${cur.pid} (${isStaleLock(cur) ? "STALE" : "live"})` : "free"}`,
          ];
          if (d.errors.length) lines.push(`errors: ${d.errors.length}`, ...d.errors.slice(0, 5).map((e) => `  ! ${e}`));
          say(ctx, lines.join("\n"), !d.errors.length && d.configOk && d.keyOk && d.pingOk ? "info" : "error");
        } else if (sub === "config") {
          if (!cfg) {
            say(
              ctx,
              [`No config found. Create ${agentDir}/omp-sync.local.json with:`, `{"endpoint": "https://<bucket-host>", "bucket": "<bucket>", "region": "auto",`, ` "accessKeyId": "...", "secretAccessKey": "..." }`, `or set OMP_SYNC_ENDPOINT/OMP_SYNC_BUCKET/OMP_SYNC_ACCESS_KEY_ID/OMP_SYNC_SECRET_ACCESS_KEY`, `plus OMP_SYNC_ENCRYPTION_KEY=$(openssl rand -base64 32)`].join("\n"),
              "warning",
            );
          } else {
            say(ctx, describeConfig(agentDir, cfg).join("\n"));
          }
        } else if (sub === "unlock") {
          // Existence and readability are separate facts: a lock file with
          // truncated JSON is a crashed writer, not an absent lock — it must
          // take the stale-removal path instead of reporting "no lock".
          if (!existsSync(lockPath(agentDir))) {
            say(ctx, "no lock present");
            return;
          }
          const cur = readLock(agentDir);
          if (cur && rest[0] !== "--stale" && !isStaleLock(cur)) {
            say(ctx, "lock is NOT stale; pass --stale to force", "warning");
            return;
          }
          rmSync(lockPath(agentDir), { force: true });
          say(ctx, cur ? `removed lock (pid ${cur.pid})` : "removed unreadable lock file");
        } else {
          say(ctx, `unknown '${sub}'. Use: ${SUBCOMMANDS.join(", ")}.`, "warning");
        }
      } catch (e) {
        if (e instanceof LockHeldError) say(ctx, e.message, "warning");
        else say(ctx, `${sub} failed: ${e instanceof Error ? e.message : String(e)}`, "error");
      }
    },
  });

  // Debounced auto-push of the current file after each turn. One small PUT
  // per quiet period — no shutdown race, no full scans on every keystroke.
  const pending = new Map<string, { ctx: ExtensionContext; timer: ReturnType<ExtensionContext["setTimeout"]> }>();
  pi.on("turn_end", (_event, ctx) => {
    let agentDir: string;
    let cfg: SyncConfig;
    try {
      agentDir = resolveAgentDir(host);
      const loaded = loadSyncConfig(agentDir);
      if (!loaded || !loaded.autoPush) return;
      cfg = loaded;
    } catch {
      return; // no config — stay silent on every turn
    }
    const current = currentSessionFile(ctx);
    if (!current) return;
    const prev = pending.get(current);
    if (prev) {
      try {
        prev.ctx.clearTimer(prev.timer);
      } catch {
        /* already fired */
      }
    }
    try {
      const timer = ctx.setTimeout(() => {
        pending.delete(current);
        const run = async (): Promise<void> => {
          // No file lock here: the process may exit mid-push (print mode,
          // shutdown budget) and orphan it. Single-file PUTs are idempotent
          // and the manifest save retries on ETag races, so this converges
          // without the lock. Manual commands still take it.
          try {
            await pushSync({ agentDir, cfg, onlyAbsPath: current });
          } catch {
            /* best effort; surfaces on the next manual status/push */
          }
        };
        void run();
      }, cfg.debounceMs);
      pending.set(current, { ctx, timer });
    } catch {
      /* timers unavailable in this mode */
    }
  });

  pi.on("session_start", (_event, ctx) => {
    let agentDir: string;
    let cfg: SyncConfig;
    try {
      agentDir = resolveAgentDir(host);
      const loaded = loadSyncConfig(agentDir);
      if (!loaded || !loaded.autoPull) return;
      cfg = loaded;
    } catch {
      return;
    }
    const current = currentSessionFile(ctx);
    // Lock-free like turn_end auto-push: idempotent PUTs + ETag manifest
    // retry converge without the lock, and no exit path can orphan it.
    const run = async (): Promise<void> => {
      try {
        const r = await pullSync({ agentDir, cfg, skipAbsPaths: current ? new Set([current]) : undefined });
        if (r.pulled || r.conflicts || r.errors.length) say(ctx, reportLine("auto-pull", r), r.errors.length ? "warning" : "info");
      } catch {
        /* best effort */
      }
    };
    void run();
  });

  // Shutdown: push the current file only. The 2s handler budget forbids a
  // full sync here by design; turn_end already carries the steady state.
  pi.on("session_shutdown", (_event, ctx) => {
    let agentDir: string;
    let cfg: SyncConfig;
    try {
      agentDir = resolveAgentDir(host);
      const loaded = loadSyncConfig(agentDir);
      if (!loaded || !loaded.autoPush) return;
      cfg = loaded;
    } catch {
      return;
    }
    void (async (): Promise<void> => {
      try {
        const current = currentSessionFile(ctx);
        if (!current) return;
        await pushSync({ agentDir, cfg, onlyAbsPath: current });
      } catch {
        /* must never block shutdown */
      }
    })();
  });
}
