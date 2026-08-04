/**
 * Background poller for gmail_snooze wake-ups and gmail_schedule_send.
 *
 * Gmail's own API has no "send later" or "un-snooze later" primitive — this
 * server has to do it itself, which only works because it is a persistent
 * process (Express on Railway), not a serverless function: it can wake itself
 * up on a timer and act. Each tick atomically claims every due row (see
 * store.ts's claimDueSnoozes/claimDueSends — `FOR UPDATE SKIP LOCKED` so two
 * overlapping ticks, or two server instances, never act on the same row
 * twice) and executes exactly the same Gmail API call an interactive tool call
 * would have made.
 */
import type { Config, User } from "./config.js";
import { userFromGoogleAccounts } from "./http.js";
import { buildUserClients, type UserClients } from "./accounts.js";
import * as store from "./store.js";

const TICK_MS = 60_000;

/** Everything the poller touches outside pure logic — overridable so tests can stub it. */
export interface SchedulerDeps {
  resolveOnboardedUser: (config: Config) => Promise<User | null>;
  buildClients: (user: User) => UserClients;
  claimDueSnoozes: typeof store.claimDueSnoozes;
  markSnoozeDone: typeof store.markSnoozeDone;
  markSnoozeFailed: typeof store.markSnoozeFailed;
  claimDueSends: typeof store.claimDueSends;
  markSendSent: typeof store.markSendSent;
  markSendFailed: typeof store.markSendFailed;
  reapStuckSends: typeof store.reapStuckSends;
}

export const defaultDeps: SchedulerDeps = {
  resolveOnboardedUser: userFromGoogleAccounts,
  buildClients: buildUserClients,
  claimDueSnoozes: store.claimDueSnoozes,
  markSnoozeDone: store.markSnoozeDone,
  markSnoozeFailed: store.markSnoozeFailed,
  claimDueSends: store.claimDueSends,
  markSendSent: store.markSendSent,
  markSendFailed: store.markSendFailed,
  reapStuckSends: store.reapStuckSends,
};

/**
 * Mirrors http.ts's handleMcp user resolution, minus the request: onboarding
 * (native OAuth) wins when enabled — that's the only mode with no static
 * per-row userToken to match against. Falls back to the stored token, then to
 * the sole configured user for single-user no-auth deployments.
 */
export async function resolveUser(config: Config, userToken: string | null, deps: SchedulerDeps = defaultDeps): Promise<User | null> {
  if (config.onboarding.enabled) {
    const u = await deps.resolveOnboardedUser(config);
    if (u) return u;
  }
  if (userToken) {
    const match = config.users.find((u) => u.token === userToken);
    if (match) return match;
  }
  return config.users[0] ?? null;
}

export async function processDueSnoozes(config: Config, deps: SchedulerDeps = defaultDeps): Promise<void> {
  const due = await deps.claimDueSnoozes(new Date());
  for (const row of due) {
    try {
      const user = await resolveUser(config, row.userToken, deps);
      if (!user) throw new Error("No Google account available to wake this snooze with.");
      const g = deps.buildClients(user).resolve(row.accountLabel);
      await g.gmail.users.messages.modify({
        userId: "me",
        id: row.messageId,
        requestBody: { addLabelIds: ["INBOX"] },
      });
      await deps.markSnoozeDone(row.id);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`[scheduler] snooze ${row.id} (${row.messageId}) failed, will retry: ${msg}`);
      await deps.markSnoozeFailed(row.id, msg);
    }
  }
}

export async function processDueSends(config: Config, deps: SchedulerDeps = defaultDeps): Promise<void> {
  const due = await deps.claimDueSends(new Date());
  for (const row of due) {
    try {
      const user = await resolveUser(config, row.userToken, deps);
      if (!user) throw new Error("No Google account available to send this message with.");
      const g = deps.buildClients(user).resolve(row.accountLabel);
      const res = await g.gmail.users.messages.send({
        userId: "me",
        requestBody: { raw: row.rawMessage },
      });
      await deps.markSendSent(row.id, res.data.id ?? "");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`[scheduler] scheduled send ${row.id} (${row.toPreview}) failed permanently: ${msg}`);
      // Not retried — see markSendFailed's comment on why a send is not idempotent.
      await deps.markSendFailed(row.id, msg);
    }
  }
}

/**
 * Reaps scheduled sends stranded in 'sending' (a process that died mid-send)
 * to 'failed' — NEVER re-sending (Gmail is not idempotent). Best-effort: logs
 * how many were reaped so the failure is at least visible in the logs, on top
 * of becoming listable via gmail_list_scheduled_sends(status='failed').
 */
export async function reapStuckSends(config: Config, deps: SchedulerDeps = defaultDeps): Promise<number> {
  const n = await deps.reapStuckSends(config.sendingStuckMinutes);
  if (n > 0) {
    console.error(
      `[scheduler] reaped ${n} scheduled send(s) stuck in 'sending' > ${config.sendingStuckMinutes}min → 'failed' (NOT re-sent; verify Sent manually)`,
    );
  }
  return n;
}

/** How many poller ticks between stuck-send sweeps (the reaper also runs at startup). */
const REAP_EVERY_TICKS = 5;

/** Starts the poller. Call once, only when a database is configured. */
export function startScheduler(config: Config, deps: SchedulerDeps = defaultDeps): void {
  // Sweep once at startup: a crash-restart is exactly when rows are stranded.
  reapStuckSends(config, deps).catch((e) =>
    console.error("[scheduler] startup reap failed:", e instanceof Error ? e.message : e),
  );
  let ticks = 0;
  const tick = async () => {
    try {
      await processDueSnoozes(config, deps);
      await processDueSends(config, deps);
      if (++ticks % REAP_EVERY_TICKS === 0) await reapStuckSends(config, deps);
    } catch (e) {
      // A tick-level failure (e.g. the database briefly unreachable) must not
      // kill the interval — log and simply try again next tick.
      console.error("[scheduler] tick failed:", e instanceof Error ? e.message : e);
    }
  };
  setInterval(tick, TICK_MS);
  console.error(`[scheduler] started — checking snoozes and scheduled sends every ${TICK_MS / 1000}s`);
}
