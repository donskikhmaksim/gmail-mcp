#!/usr/bin/env node
/**
 * Offline check of the poller in src/scheduler.ts — the piece that actually
 * wakes snoozes and fires scheduled sends. Every external touchpoint (store
 * queries, Google clients, onboarded-user lookup) is injected via the `deps`
 * parameter scheduler.ts exposes for exactly this purpose, so no database, no
 * network, and no real Gmail account are involved.
 *
 * Usage:
 *   npm test                       # builds, then runs both test scripts
 *   node scripts/test-scheduler.mjs
 */
import { processDueSnoozes, processDueSends, resolveUser } from "../dist/scheduler.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};

function fakeConfig({ onboardingEnabled = false, users = [], sendingStuckMinutes = 10 } = {}) {
  return { onboarding: { enabled: onboardingEnabled }, users, sendingStuckMinutes };
}

function fakeDeps(overrides = {}) {
  const calls = { modify: [], send: [], done: [], failed: [], sendOk: [], sendFailed: [], reaped: [] };
  const clientsFor = new Map(); // userName -> { resolve(label) -> gmail client }
  const deps = {
    resolveOnboardedUser: async () => null,
    buildClients: (user) => {
      const byLabel = clientsFor.get(user.name) ?? new Map();
      return {
        resolve: (label) => {
          if (!byLabel.has(label)) {
            byLabel.set(label, {
              gmail: {
                users: {
                  messages: {
                    modify: async (args) => {
                      calls.modify.push(args);
                      return { data: {} };
                    },
                    send: async (args) => {
                      calls.send.push(args);
                      return { data: { id: "SENTID" } };
                    },
                    // Post-verify (B3) reads the sent message back. A normal
                    // send lands in Sent only — labelIds ["SENT"], not INBOX.
                    get: async (args) => {
                      calls.postVerifyGet = (calls.postVerifyGet ?? []);
                      calls.postVerifyGet.push(args);
                      return { data: { labelIds: ["SENT"], payload: { headers: [{ name: "To", value: "a@b.com" }, { name: "Subject", value: "S" }] } } };
                    },
                  },
                },
              },
            });
          }
          return byLabel.get(label);
        },
      };
    },
    claimDueSnoozes: async () => [],
    markSnoozeDone: async (id) => calls.done.push(id),
    markSnoozeFailed: async (id, err) => calls.failed.push({ id, err }),
    claimDueSends: async () => [],
    markSendSent: async (id, msgId) => calls.sendOk.push({ id, msgId }),
    markSendFailed: async (id, err) => calls.sendFailed.push({ id, err }),
    reapStuckSends: async (mins) => { calls.reaped.push(mins); return 0; },
    ...overrides,
  };
  return { deps, calls };
}

// --- 1. resolveUser: onboarding wins when enabled -------------------------

console.log("\n[1] resolveUser — onboarding takes priority");
{
  const onboardedUser = { name: "owner@x.com", accounts: [], defaultAccount: "personal" };
  const { deps } = fakeDeps({ resolveOnboardedUser: async () => onboardedUser });
  const config = fakeConfig({ onboardingEnabled: true, users: [{ token: "T1", name: "other" }] });
  const u = await resolveUser(config, "T1", deps);
  check("returns the onboarded user, ignoring the token match", u === onboardedUser);
}

console.log("\n[2] resolveUser — falls back to token match when onboarding is off/empty");
{
  const userA = { token: "TA", name: "a" };
  const userB = { token: "TB", name: "b" };
  const { deps } = fakeDeps();
  const config = fakeConfig({ onboardingEnabled: false, users: [userA, userB] });
  check("matches by token", (await resolveUser(config, "TB", deps)) === userB);
  check("falls back to users[0] when token matches nothing", (await resolveUser(config, "NOPE", deps)) === userA);
  check("falls back to users[0] when token is null", (await resolveUser(config, null, deps)) === userA);
}

console.log("\n[3] resolveUser — onboarding enabled but returns null falls through to token/users[0]");
{
  const userA = { token: "TA", name: "a" };
  const { deps } = fakeDeps({ resolveOnboardedUser: async () => null });
  const config = fakeConfig({ onboardingEnabled: true, users: [userA] });
  check("falls back when onboarded lookup yields nothing", (await resolveUser(config, null, deps)) === userA);
}

// --- 4-6. processDueSnoozes ------------------------------------------------

console.log("\n[4] processDueSnoozes — wakes a due snooze, marks it done");
{
  const owner = { name: "owner@x.com", accounts: [], defaultAccount: "personal" };
  const row = { id: 1, userToken: null, accountLabel: "personal", messageId: "MSG1" };
  const { deps, calls } = fakeDeps({
    resolveOnboardedUser: async () => owner,
    claimDueSnoozes: async () => [row],
  });
  const config = fakeConfig({ onboardingEnabled: true });
  await processDueSnoozes(config, deps);
  check("modify() called to re-add INBOX", calls.modify.length === 1, JSON.stringify(calls.modify));
  check("correct message id targeted", calls.modify[0].id === "MSG1");
  check("INBOX label re-added", calls.modify[0].requestBody.addLabelIds.includes("INBOX"));
  check("marked done, not failed", calls.done.length === 1 && calls.failed.length === 0, JSON.stringify(calls));
}

console.log("\n[5] processDueSnoozes — no user resolvable -> marked failed (retried next tick), never done");
{
  const row = { id: 2, userToken: null, accountLabel: "personal", messageId: "MSG2" };
  const { deps, calls } = fakeDeps({
    resolveOnboardedUser: async () => null,
    claimDueSnoozes: async () => [row],
  });
  const config = fakeConfig({ onboardingEnabled: true, users: [] });
  await processDueSnoozes(config, deps);
  check("nothing archived — no client to call", calls.modify.length === 0);
  check("marked failed for retry", calls.failed.length === 1 && calls.failed[0].id === 2, JSON.stringify(calls.failed));
  check("never marked done", calls.done.length === 0);
}

console.log("\n[6] processDueSnoozes — one failing row doesn't stop the others in the same tick");
{
  const owner = { name: "owner@x.com", accounts: [], defaultAccount: "personal" };
  const rows = [
    { id: 10, userToken: null, accountLabel: "personal", messageId: "BAD" },
    { id: 11, userToken: null, accountLabel: "personal", messageId: "GOOD" },
  ];
  const { deps, calls } = fakeDeps({ resolveOnboardedUser: async () => owner, claimDueSnoozes: async () => rows });
  deps.buildClients = (user) => ({
    resolve: () => ({
      gmail: {
        users: {
          messages: {
            modify: async (args) => {
              if (args.id === "BAD") throw new Error("Gmail said no");
              calls.modify.push(args);
              return { data: {} };
            },
          },
        },
      },
    }),
  });
  const config = fakeConfig({ onboardingEnabled: true });
  await processDueSnoozes(config, deps);
  check("the good row still got archived", calls.modify.length === 1 && calls.modify[0].id === "GOOD", JSON.stringify(calls.modify));
  check("the bad row is marked failed", calls.failed.some((f) => f.id === 10), JSON.stringify(calls.failed));
  check("the good row is marked done", calls.done.includes(11), JSON.stringify(calls.done));
}

// --- 7-8. processDueSends ---------------------------------------------------

console.log("\n[7] processDueSends — sends the exact stored raw message, marks sent");
{
  const owner = { name: "owner@x.com", accounts: [], defaultAccount: "personal" };
  const row = { id: 5, userToken: null, accountLabel: "personal", rawMessage: "UkFXX0RBVEE=", toPreview: "a@b.com" };
  const { deps, calls } = fakeDeps({ resolveOnboardedUser: async () => owner, claimDueSends: async () => [row] });
  const config = fakeConfig({ onboardingEnabled: true });
  await processDueSends(config, deps);
  check("send() called with the stored raw bytes verbatim", calls.send[0]?.requestBody?.raw === "UkFXX0RBVEE=", JSON.stringify(calls.send));
  check("marked sent with Gmail's returned id", calls.sendOk[0]?.id === 5 && calls.sendOk[0]?.msgId === "SENTID", JSON.stringify(calls.sendOk));
}

console.log("\n[8] processDueSends — failure is terminal (not retried), unlike a snooze");
{
  const owner = { name: "owner@x.com", accounts: [], defaultAccount: "personal" };
  const row = { id: 6, userToken: null, accountLabel: "personal", rawMessage: "X", toPreview: "a@b.com" };
  const { deps, calls } = fakeDeps({ resolveOnboardedUser: async () => owner, claimDueSends: async () => [row] });
  deps.buildClients = () => ({
    resolve: () => ({ gmail: { users: { messages: { send: async () => { throw new Error("quota exceeded"); } } } } }),
  });
  const config = fakeConfig({ onboardingEnabled: true });
  await processDueSends(config, deps);
  check("marked failed (terminal), never sent", calls.sendFailed.length === 1 && calls.sendOk.length === 0, JSON.stringify(calls));
  check("error message preserved", /quota exceeded/.test(calls.sendFailed[0]?.err ?? ""), JSON.stringify(calls.sendFailed));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
