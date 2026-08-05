#!/usr/bin/env node
/**
 * Offline test for package A1 (consent-manifest + audit storage,
 * `src/store.ts`'s `consent_manifests`/`consent_audit` functions).
 *
 * There is no live Postgres in this environment/CI, and hitting the real
 * shared instance (all 5 MCP servers point at ONE physical Postgres — plan
 * §0.4) from an automated test run would risk writing throwaway rows into a
 * database other servers depend on. Per the task's explicit fallback ("сделай
 * на fake/in-memory реализации SQL-логики ИЛИ пропусти с явным skip-
 * сообщением"), this file takes the fake/in-memory route — same choice
 * `scripts/test-consent.mjs` already made for `src/consent.ts`'s pure logic.
 *
 * The fake below reproduces, in JS, the EXACT predicates store.ts's real SQL
 * uses (same WHERE clauses, same COALESCE semantics, same "delete expired
 * AWAITING rows on create" sweep) — it is a spec-conformance test of the
 * atomicity/isolation CONTRACT store.ts must implement, not a substitute for
 * hitting real Postgres. store.ts's actual query text/parameter binding is
 * additionally checked by `npm run typecheck` (return types match
 * consent.ts's `ConsentStore` exactly, enforced via the `: ConsentStore`
 * annotation on `consentStoreAdapter` in server.ts) and by manual review
 * against the `consumeCode` atomic-UPDATE precedent it was modelled on.
 *
 * Usage: node scripts/test-a1-manifests.mjs
 */
import { loadConsentGateConfig } from "../src/config.ts";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};

// ── [0] config.ts: env defaults for the gate's knobs ────────────────────────
console.log("\n[0] loadConsentGateConfig — env defaults and overrides");
{
  const saved = {
    CONSENT_SERVER: process.env.CONSENT_SERVER,
    CONSENT_TTL_MS: process.env.CONSENT_TTL_MS,
    MIN_CONSENT_GAP_MS: process.env.MIN_CONSENT_GAP_MS,
    SEND_BATCH_MAX: process.env.SEND_BATCH_MAX,
  };
  for (const k of Object.keys(saved)) delete process.env[k];

  const defaults = loadConsentGateConfig();
  check("default server = gmail", defaults.server === "gmail", defaults.server);
  check("default CONSENT_TTL_MS = 3600000 (1h)", defaults.consentTtlMs === 3_600_000, defaults.consentTtlMs);
  check(
    "default MIN_CONSENT_GAP_MS = 10000 (Q3 2026-08-04, NOT the generic 5000)",
    defaults.minConsentGapMs === 10_000,
    defaults.minConsentGapMs,
  );
  check("default SEND_BATCH_MAX = 10", defaults.sendBatchMax === 10, defaults.sendBatchMax);

  process.env.CONSENT_SERVER = "sheets";
  process.env.CONSENT_TTL_MS = "60000";
  process.env.MIN_CONSENT_GAP_MS = "2500";
  process.env.SEND_BATCH_MAX = "3";
  const overridden = loadConsentGateConfig();
  check("server overridden", overridden.server === "sheets", overridden.server);
  check("TTL overridden", overridden.consentTtlMs === 60_000, overridden.consentTtlMs);
  check("gap overridden", overridden.minConsentGapMs === 2_500, overridden.minConsentGapMs);
  check("batch cap overridden", overridden.sendBatchMax === 3, overridden.sendBatchMax);

  process.env.SEND_BATCH_MAX = "not-a-number";
  check("garbage env falls back to default, not NaN", loadConsentGateConfig().sendBatchMax === 10, loadConsentGateConfig().sendBatchMax);

  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

// ── fake in-memory SQL layer — mirrors store.ts's real WHERE/COALESCE logic ─

function makeFakeSqlStore(clock) {
  const manifests = new Map(); // id -> row
  const audits = new Map(); // id -> row

  return {
    manifests,
    audits,

    // Mirrors: DELETE FROM consent_manifests WHERE server=$1 AND
    // status='AWAITING_CONSENT' AND expires_at < $2; then INSERT.
    async createManifest(input) {
      for (const [id, r] of manifests) {
        if (r.server === input.server && r.status === "AWAITING_CONSENT" && r.expiresAt < clock.t) {
          manifests.delete(id);
        }
      }
      manifests.set(input.id, {
        id: input.id,
        server: input.server,
        tool: input.tool,
        accountLabel: input.accountLabel,
        payload: input.payload,
        objectHash: input.objectHash,
        status: "AWAITING_CONSENT",
        createdAt: input.createdAt,
        expiresAt: input.expiresAt,
        consumedAt: null,
        userReply: null,
      });
    },

    // Mirrors: SELECT * FROM consent_manifests WHERE id=$1 AND server=$2.
    async getManifest(id, server) {
      const r = manifests.get(id);
      if (!r || r.server !== server) return null;
      return { ...r };
    },

    // Mirrors the atomic UPDATE ... WHERE id=$1 AND server=$2 AND
    // status='AWAITING_CONSENT' AND expires_at > $4 RETURNING *.
    async consumeManifest(id, server, userReply) {
      const r = manifests.get(id);
      if (!r || r.server !== server) return null;
      if (r.status !== "AWAITING_CONSENT") return null;
      if (!(r.expiresAt > clock.t)) return null; // expires_at > now, strict
      r.status = "DONE";
      r.consumedAt = clock.t;
      r.userReply = userReply;
      return { ...r };
    },

    // Mirrors: UPDATE ... SET status='INVALIDATED' WHERE id=$1 AND server=$2
    // AND status='AWAITING_CONSENT' (no-op otherwise).
    async invalidateManifest(id, server, userReply) {
      const r = manifests.get(id);
      if (r && r.server === server && r.status === "AWAITING_CONSENT") {
        r.status = "INVALIDATED";
        r.userReply = userReply;
      }
    },

    async appendConsentAudit(entry) {
      audits.set(entry.id, { ...entry, postVerifyResult: null, error: null, preSnapshot: null });
    },

    // Mirrors: UPDATE consent_audit SET outcome=COALESCE($2,outcome), ...
    // WHERE id=$1 — only overwrites fields that were actually passed.
    async updateConsentAuditOutcome(auditId, outcome) {
      const a = audits.get(auditId);
      if (!a) return;
      if (outcome.outcome !== undefined && outcome.outcome !== null) a.outcome = outcome.outcome;
      if (outcome.postVerify !== undefined && outcome.postVerify !== null) a.postVerifyResult = outcome.postVerify;
      if (outcome.error !== undefined && outcome.error !== null) a.error = outcome.error;
      if (outcome.preSnapshot !== undefined) a.preSnapshot = outcome.preSnapshot;
    },

    async listConsentAudit(filters, limit = 20) {
      const cap = Math.min(Math.max(Math.trunc(limit) || 20, 1), 100);
      return [...audits.values()]
        .filter((a) => a.server === filters.server)
        .filter((a) => filters.since == null || a.ts >= filters.since)
        .filter((a) => filters.until == null || a.ts <= filters.until)
        .filter((a) => !filters.accountLabel || a.accountLabel === filters.accountLabel)
        .filter((a) => !filters.tool || a.tool === filters.tool)
        .filter((a) => !filters.outcome || a.outcome === filters.outcome)
        .sort((x, y) => y.ts - x.ts)
        .slice(0, cap);
    },
  };
}

const clock = { t: 1_700_000_000_000 };
const PAYLOAD = { account: "work", messages: [{ to: "eric@x.com", subject: "Quote" }] };

function newManifestArgs(overrides = {}) {
  return {
    id: overrides.id ?? `m-${Math.random().toString(36).slice(2)}`,
    server: overrides.server ?? "gmail",
    tool: overrides.tool ?? "gmail_send",
    accountLabel: overrides.accountLabel ?? "work",
    payload: PAYLOAD,
    objectHash: "hash1",
    createdAt: clock.t,
    expiresAt: clock.t + 3_600_000,
    ...overrides,
  };
}

// ── [1] double consumeManifest: second call is empty ────────────────────────
console.log("\n[1] double consumeManifest — first succeeds, repeat returns null (one-shot)");
{
  const store = makeFakeSqlStore(clock);
  const args = newManifestArgs({ id: "m1" });
  await store.createManifest(args);
  const first = await store.consumeManifest("m1", "gmail", "да, отправляй");
  check("first consume succeeds", first !== null && first.status === "DONE", JSON.stringify(first));
  check("consumedAt stamped", first.consumedAt === clock.t, first.consumedAt);
  check("userReply recorded verbatim", first.userReply === "да, отправляй", first.userReply);
  const second = await store.consumeManifest("m1", "gmail", "да, отправляй");
  check("second consume — empty (already DONE)", second === null, JSON.stringify(second));
}

// ── [2] expired manifest does not consume ────────────────────────────────────
console.log("\n[2] expired manifest — consumeManifest returns null, status untouched");
{
  const store = makeFakeSqlStore(clock);
  const args = newManifestArgs({ id: "m2", expiresAt: clock.t + 1_000 });
  await store.createManifest(args);
  clock.t += 2_000; // past expiry
  const res = await store.consumeManifest("m2", "gmail", "да");
  check("expired — consume returns null", res === null, JSON.stringify(res));
  const row = await store.getManifest("m2", "gmail");
  check("row still AWAITING_CONSENT (not silently flipped)", row.status === "AWAITING_CONSENT", row.status);
  clock.t = 1_700_000_000_000; // reset
}

// ── [3] invalidated manifest does not consume ────────────────────────────────
console.log("\n[3] invalidated manifest — consumeManifest returns null");
{
  const store = makeFakeSqlStore(clock);
  const args = newManifestArgs({ id: "m3" });
  await store.createManifest(args);
  await store.invalidateManifest("m3", "gmail", "нет, отмена");
  const row = await store.getManifest("m3", "gmail");
  check("status flipped to INVALIDATED", row.status === "INVALIDATED", row.status);
  check("userReply of the negation recorded", row.userReply === "нет, отмена", row.userReply);
  const res = await store.consumeManifest("m3", "gmail", "да");
  check("invalidated — consume returns null", res === null, JSON.stringify(res));
  // Invalidating an already-consumed/invalidated row is a no-op, not an error.
  const before = { ...(await store.getManifest("m3", "gmail")) };
  await store.invalidateManifest("m3", "gmail", "да опять");
  const after = await store.getManifest("m3", "gmail");
  check("re-invalidating an INVALIDATED row is a no-op", after.userReply === before.userReply, after.userReply);
}

// ── [4] server isolation: a row from one server is invisible to another ─────
console.log("\n[4] server isolation — gmail's manifest invisible/unconsumable from sheets, and vice versa");
{
  const store = makeFakeSqlStore(clock);
  await store.createManifest(newManifestArgs({ id: "m4", server: "gmail" }));
  const wrongServerGet = await store.getManifest("m4", "sheets");
  check("getManifest under wrong server → null", wrongServerGet === null, JSON.stringify(wrongServerGet));
  const wrongServerConsume = await store.consumeManifest("m4", "sheets", "да");
  check("consumeManifest under wrong server → null", wrongServerConsume === null, JSON.stringify(wrongServerConsume));
  const stillLive = await store.getManifest("m4", "gmail");
  check("row untouched by the cross-server attempt", stillLive.status === "AWAITING_CONSENT", stillLive.status);
  // `id` is the table's PRIMARY KEY (a randomUUID — globally unique in
  // practice, not composite with `server`), so two servers never legitimately
  // share a row id; isolation instead comes entirely from every query
  // filtering `WHERE id=$1 AND server=$2`, which the three checks above cover.
  // A second, distinctly-id'd manifest for another server just proves the two
  // don't interfere with each other at all:
  await store.createManifest(newManifestArgs({ id: "m4-sheets", server: "sheets", tool: "sheets_write_range" }));
  const gmailSide = await store.getManifest("m4", "gmail");
  const sheetsSide = await store.getManifest("m4-sheets", "sheets");
  check("independent manifests on different servers coexist", gmailSide.tool === "gmail_send" && sheetsSide.tool === "sheets_write_range", JSON.stringify({ gmailSide, sheetsSide }));
  const consumedGmail = await store.consumeManifest("m4", "gmail", "да");
  check("consuming gmail's copy doesn't touch sheets'", consumedGmail?.status === "DONE" && (await store.getManifest("m4-sheets", "sheets")).status === "AWAITING_CONSENT");
}

// ── [5] two-phase audit: create → append(confirmed) → updateOutcome ─────────
console.log("\n[5] two-phase audit — appendConsentAudit (decision) then updateConsentAuditOutcome (mutation result)");
{
  const store = makeFakeSqlStore(clock);
  const args = newManifestArgs({ id: "m5" });
  await store.createManifest(args);
  const consumed = await store.consumeManifest("m5", "gmail", "да, отправляй");
  check("manifest confirmed", consumed !== null);

  // Phase 1 — decision (what consent.ts writes right after consumeManifest succeeds).
  const auditId = "a5";
  await store.appendConsentAudit({
    id: auditId,
    ts: clock.t,
    server: "gmail",
    tool: "gmail_send",
    accountLabel: "work",
    manifestId: "m5",
    objectHash: "hash1",
    userReply: "да, отправляй",
    checks: { manifest: "ok", antiDoublet: "ok", reply: "affirmation", binding: "ok", oneShot: "ok" },
    outcome: "confirmed",
    actor: "human",
  });
  let audit = (await store.listConsentAudit({ server: "gmail" }, 20))[0];
  check("phase 1: audit row exists right after the decision", audit?.id === auditId, JSON.stringify(audit));
  check("phase 1: user_reply recorded verbatim", audit.userReply === "да, отправляй");
  check("phase 1: post_verify/error still empty — mutation hasn't happened yet", audit.postVerifyResult === null && audit.error === null);

  // Phase 2 — a later package (A3) calls this AFTER actually sending, with the
  // pre-snapshot + post-verify result. Must NOT clobber phase-1 fields.
  await store.updateConsentAuditOutcome(auditId, {
    outcome: "confirmed",
    postVerify: "✅ Отправлено, To совпал, не self-send",
    preSnapshot: { to: "eric@x.com", subject: "Quote" },
  });
  audit = (await store.listConsentAudit({ server: "gmail" }, 20))[0];
  check("phase 2: post_verify_result filled in", /✅/.test(audit.postVerifyResult ?? ""), audit.postVerifyResult);
  check("phase 2: pre_snapshot filled in (extra field beyond ConsentStore's contract)", audit.preSnapshot?.to === "eric@x.com", JSON.stringify(audit.preSnapshot));
  check("phase 2: user_reply/checks from phase 1 untouched", audit.userReply === "да, отправляй" && audit.checks.oneShot === "ok");

  // A failed mutation goes through the same second phase, just with `error` set.
  await store.updateConsentAuditOutcome(auditId, { outcome: "failed", error: "Gmail API: quota exceeded" });
  audit = (await store.listConsentAudit({ server: "gmail" }, 20))[0];
  check("phase 2 (failure path): outcome overwritten to failed", audit.outcome === "failed", audit.outcome);
  check("phase 2 (failure path): error recorded", audit.error === "Gmail API: quota exceeded", audit.error);
  check("phase 2 (failure path): earlier post_verify not clobbered by COALESCE semantics", /✅/.test(audit.postVerifyResult ?? ""));
}

// ── [6] audit written on refusal and on invalidation, not just success ──────
console.log("\n[6] audit rows for refusal and invalidation outcomes (not only confirmed)");
{
  const store = makeFakeSqlStore(clock);
  await store.appendConsentAudit({
    id: "a6-refused",
    ts: clock.t,
    server: "gmail",
    tool: "gmail_send",
    accountLabel: "work",
    manifestId: "m6",
    objectHash: null,
    userReply: "наверное как-нибудь потом",
    checks: { reply: "unknown" },
    outcome: "refused",
    refusalReason: "Не понял ответ",
    actor: "human",
  });
  await store.appendConsentAudit({
    id: "a6-invalidated",
    ts: clock.t + 1,
    server: "gmail",
    tool: "gmail_send",
    accountLabel: "work",
    manifestId: "m6",
    objectHash: null,
    userReply: "нет, не отправляй",
    checks: { reply: "negation" },
    outcome: "invalidated",
    actor: "human",
  });
  const rows = await store.listConsentAudit({ server: "gmail", tool: "gmail_send" }, 20);
  check("both non-success outcomes are present in the log", rows.some((r) => r.outcome === "refused") && rows.some((r) => r.outcome === "invalidated"), JSON.stringify(rows.map((r) => r.outcome)));
}

// ── [7] listConsentAudit filters + limit cap (limits-audit.md §10.1) ────────
console.log("\n[7] listConsentAudit — server-scoped, filterable, capped at 100");
{
  const store = makeFakeSqlStore(clock);
  for (let i = 0; i < 5; i++) {
    await store.appendConsentAudit({
      id: `a7-${i}`,
      ts: clock.t + i,
      server: i % 2 === 0 ? "gmail" : "sheets",
      tool: "gmail_send",
      accountLabel: "work",
      userReply: "да",
      checks: {},
      outcome: "confirmed",
      actor: "human",
    });
  }
  const gmailOnly = await store.listConsentAudit({ server: "gmail" }, 20);
  check("only gmail's own rows come back", gmailOnly.every((r) => r.server === "gmail") && gmailOnly.length === 3, JSON.stringify(gmailOnly.map((r) => r.id)));
  const newestFirst = await store.listConsentAudit({ server: "gmail" }, 20);
  check("newest first", newestFirst[0].ts >= newestFirst.at(-1).ts);
  const capped = await store.listConsentAudit({ server: "gmail" }, 1000);
  check("limit silently capped, doesn't crash on an absurd ask", capped.length <= 100, capped.length);
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
