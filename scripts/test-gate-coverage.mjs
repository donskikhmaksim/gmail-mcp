#!/usr/bin/env node
/**
 * A3/T1 — reflexive gate-coverage test (plan §A3 «Системные тесты», extended
 * by package T1 for the priority-2 write tools).
 *
 * Unlike every other test file here, this one does NOT hand-pick which tools
 * to exercise. It lists the tools from the REAL registered MCP registry
 * (`client.listTools()`, i.e. what a model actually sees) and, for every tool
 * classified as a write (no `readOnlyHint: true` — the exact rule the task
 * specifies), checks it against an explicit allowlist:
 *
 *  - every entry in `GATED_TOOLS` (the 4 A3 send tools PLUS T1's 11
 *    priority-2 tools) gets a real BEHAVIOURAL check: calling it WITHOUT
 *    manifest_id/user_reply must not reach ANY mutating fake API call, and
 *    the response must look like a plan, not a success/failure header;
 *  - everything else that is a write MUST be named in `UNGATED_WRITE_ALLOWLIST`
 *    below, with a one-line reason. A write tool that is neither gated nor
 *    allowlisted fails this test — that's the point: a new write landing in
 *    gmail.ts without going through requireConsent (or being consciously
 *    exempted) breaks CI instead of shipping silently ungated.
 *
 * After T1, only TWO tools remain in the allowlist, both with the
 * orchestrator's explicit per-tool verdict (2026-08-04) as reason, not a
 * placeholder: gmail_cancel_scheduled_send (itself protective — it cancels a
 * send) and gmail_get_attachment_text (read/OCR; its transient Google Doc
 * gets a reliable finally-cleanup, not a gate).
 *
 * Usage: node scripts/test-gate-coverage.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";
import { registerAccountTools } from "../dist/accounts.js";
import { initDownloads } from "../dist/downloads.js";
import { registeredAutoExecuteTools } from "../dist/autoExecute.js";

// gmail_get_download_url refuses before the gate when the server doesn't know
// its own public URL — give it one so the gate itself is what gets exercised.
initDownloads("https://mail.example.test");

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};
const text = (r) => r.content[0].text;

// ── explicit allowlist of write tools NOT (yet) behind the consent gate ─────
// Each entry names WHY it is here, so the list can't silently grow without a
// reason attached. Keep this in sync with plan §1's priority table — moving a
// tool INTO the gate (T1 and later) means deleting its line here, and the
// test then demands it show up in GATED_TOOLS with real coverage instead.
// Reasons below are the orchestrator's explicit per-tool verdict (2026-08-04),
// not a placeholder — earlier drafts had vague "stage-6 audit decides" text
// for 3 of these; that has been replaced with the actual decision so this
// list can't be mistaken for still-pending triage.
const UNGATED_WRITE_ALLOWLIST = {
  gmail_cancel_scheduled_send: "защитное действие (отмена отправки), сознательно вне гейта",
  gmail_get_attachment_text: "по сути read (OCR), Drive-файл временный — надёжный finally-cleanup, не гейт",
};

/** Every tool the gate covers (A3's 4 send tools + T1's 11 priority-2 tools),
 * with how to reach its plan phase, which counter must stay at 0 after a
 * plan-only call, and whether it is expected to carry `destructiveHint: true`
 * (irreversible — trash/delete_label) vs `false` (additive/reversible —
 * everything else in T1, per Maksim's item-7 classification). */
const GATED_TOOLS = {
  gmail_send: { args: { messages: [{ to: "a@x.com", subject: "S", body: "B" }] }, counterKey: "send", destructive: true },
  gmail_reply: { args: { replies: [{ messageId: "M1", body: "B" }] }, counterKey: "draftsSend", destructive: true },
  gmail_forward: { args: { items: [{ messageId: "M1", to: "b@x.com" }] }, counterKey: "send", destructive: true },
  gmail_schedule_send: {
    args: { messages: [{ to: "c@x.com", subject: "S", body: "B", sendAt: "2099-01-01T08:00:00-07:00" }] },
    counterKey: "addScheduledSend",
    destructive: true,
  },
  // ── T1 priority-2 tools ────────────────────────────────────────────────
  gmail_create_draft: { args: { drafts: [{ to: "a@x.com", subject: "S", body: "B" }] }, counterKey: "draftsCreate", destructive: false },
  gmail_archive: { args: { messageIds: ["M1"] }, counterKey: "modify", destructive: false },
  gmail_trash: { args: { messageIds: ["M1"] }, counterKey: "trash", destructive: true },
  gmail_modify_labels: { args: { items: [{ messageId: "M1", addLabelIds: ["STARRED"] }] }, counterKey: "modify", destructive: false },
  gmail_snooze: { args: { items: [{ messageId: "M1", unsnoozeAt: "2099-01-01T09:00:00" }] }, counterKey: "modify", destructive: false },
  gmail_create_label: { args: { labels: [{ name: "Vendors/Acme" }] }, counterKey: "labelCreate", destructive: false },
  gmail_update_label: { args: { items: [{ labelId: "L1", name: "New name" }] }, counterKey: "labelPatch", destructive: false },
  gmail_delete_label: { args: { labelIds: ["L1"] }, counterKey: "labelDelete", destructive: true },
  gmail_save_attachment_to_drive: {
    args: { items: [{ messageId: "M1", attachmentId: "ATT1" }] },
    counterKey: "driveCreate",
    destructive: false,
  },
  gmail_export_thread_eml: { args: { threadId: "T1" }, counterKey: "driveCreate", destructive: false },
  gmail_create_upload_session: { args: { files: [{ name: "big.pdf" }] }, counterKey: "driveCreate", destructive: false },
  // Выдача ссылки-доступа на вложение. Раньше стояла с `readOnlyHint: true` и
  // вызывалась без единой кнопки — «только чтение» здесь ложь: ссылка САМА
  // является доступом (скачает любой, у кого она есть; отозвать нельзя).
  // Мутация тут не проходит через фейковый Google-клиент (ссылка пишется в
  // хранилище ссылок сервера), поэтому вместо счётчика вызовов проверяется
  // прямое доказательство: в ответе фазы плана нет ни одной выданной ссылки.
  gmail_get_download_url: {
    args: { items: [{ messageId: "M1", attachmentId: "ATT1" }] },
    counterKey: null,
    planMustNotContain: "/dl/",
    destructive: false,
  },
};

// ── fakes (same shape as scripts/test-a3-gate.mjs, kept self-contained here
//    since this file's job is enumeration, not gate-logic depth) ────────────

function makeConsentStore() {
  const manifests = new Map();
  return {
    manifests,
    async createManifest(input) {
      manifests.set(input.id, { ...input, status: "AWAITING_CONSENT", consumedAt: null, userReply: null });
    },
    async getManifest(id, server) {
      const r = manifests.get(id);
      return r && r.server === server ? { ...r } : null;
    },
    async consumeManifest() {
      return null; // this test never confirms — only the plan phase is exercised
    },
    async invalidateManifest() {},
    async appendConsentAudit() {},
    async updateConsentAuditOutcome() {},
  };
}
const CONSENT_CFG = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10 };

function makeCounters() {
  return {
    send: 0,
    draftsCreate: 0,
    draftsSend: 0,
    addScheduledSend: 0,
    modify: 0,
    trash: 0,
    labelCreate: 0,
    labelPatch: 0,
    labelDelete: 0,
    driveCreate: 0,
  };
}

function buildClients(counters) {
  // format-aware: "full" additionally returns a MIME part with an attachment
  // (id ATT1) so gmail_save_attachment_to_drive's plan phase (which reads the
  // MIME tree to locate the attachment by id) can find a match without
  // erroring out — this file only needs the PLAN phase to succeed, real
  // execute-phase behaviour is covered by scripts/test-t1-gate.mjs.
  const getImpl = async ({ format } = {}) => {
    const payload = { headers: [{ name: "From", value: "eric@x.com" }, { name: "Subject", value: "Hi" }] };
    if (format === "full") {
      payload.parts = [{ filename: "f.pdf", mimeType: "application/pdf", body: { attachmentId: "ATT1", size: 10 } }];
    }
    return { data: { labelIds: ["SENT", "INBOX"], payload } };
  };
  return {
    names: ["work"],
    defaultName: "work",
    multi: false,
    resolve: () => ({
      gmail: {
        users: {
          getProfile: async () => ({ data: { emailAddress: "me@x.com" } }),
          labels: {
            list: async () => ({ data: { labels: [] } }),
            get: async ({ id }) => ({ data: { id, name: "Existing label" } }),
            create: async ({ requestBody }) => {
              counters.labelCreate++;
              return { data: { id: "L" + counters.labelCreate, name: requestBody.name } };
            },
            patch: async ({ id }) => {
              counters.labelPatch++;
              return { data: { id, name: "Patched" } };
            },
            delete: async () => {
              counters.labelDelete++;
            },
          },
          threads: {
            get: async () => ({ data: { messages: [{ payload: { headers: [{ name: "Subject", value: "Thread" }] } }] } }),
          },
          messages: {
            send: async () => {
              counters.send++;
              return { data: { id: "SID" + counters.send, threadId: "T1" } };
            },
            get: getImpl,
            modify: async () => {
              counters.modify++;
              return { data: {} };
            },
            trash: async () => {
              counters.trash++;
              return { data: {} };
            },
            list: async () => ({ data: { resultSizeEstimate: 0 } }),
            attachments: { get: async () => ({ data: { data: "", size: 0 } }) },
          },
          drafts: {
            create: async () => {
              counters.draftsCreate++;
              return { data: { id: "DRAFT" + counters.draftsCreate } };
            },
            send: async () => {
              counters.draftsSend++;
              return { data: { id: "SID" + counters.draftsSend } };
            },
          },
        },
      },
      drive: {
        files: {
          list: async () => ({ data: { files: [] } }),
          create: async ({ requestBody }) => {
            counters.driveCreate++;
            return { data: { id: "F" + counters.driveCreate, name: requestBody?.name } };
          },
          get: async ({ fileId }) => ({ data: { id: fileId, name: "f", trashed: false } }),
        },
      },
      accessToken: async () => "fake-token",
    }),
    canonicalName: (n) => (n && n.trim() ? n.trim() : "work"),
    emailFor: () => "me@x.com",
    baseGmailQuery: () => "",
  };
}

function buildPgStore(counters) {
  return {
    addSnooze: async () => {},
    addScheduledSend: async () => {
      counters.addScheduledSend++;
      return counters.addScheduledSend;
    },
    listScheduledSends: async () => [],
    countScheduledSends: async () => 0,
    cancelScheduledSend: async () => false,
  };
}

async function harness() {
  const counters = makeCounters();
  const clients = buildClients(counters);
  const consentStore = makeConsentStore();
  const server = new McpServer({ name: "gate-coverage", version: "0" });
  registerAccountTools(server, clients);
  registerGmailTools(server, clients, {
    store: buildPgStore(counters),
    userToken: null,
    consentStore,
    consentCfg: CONSENT_CFG,
  });
  const cli = new Client({ name: "c", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), cli.connect(a)]);
  return { cli, counters };
}

// ═══ enumerate the REAL registry, classify, and cross-check ═════════════════

console.log("\n[1] enumerate registered tools from the real MCP registry (client.listTools())");
const { cli, counters } = await harness();
const tools = (await cli.listTools()).tools;
check("registry is non-empty (sanity)", tools.length > 10, String(tools.length));

const writes = tools.filter((t) => t.annotations?.readOnlyHint !== true);
const reads = tools.filter((t) => t.annotations?.readOnlyHint === true);
console.log(`   ${tools.length} tool(s) total: ${reads.length} read-only, ${writes.length} write`);

console.log("\n[2] every write tool is EITHER one of the 4 gated tools OR in the explicit allowlist");
const unexpected = [];
for (const t of writes) {
  const gated = t.name in GATED_TOOLS;
  const allowlisted = t.name in UNGATED_WRITE_ALLOWLIST;
  check(`${t.name} — gated or allowlisted`, gated || allowlisted, `neither (new ungated write tool!)`);
  if (!gated && !allowlisted) unexpected.push(t.name);
}
check(
  "no unexpected ungated write tools slipped in",
  unexpected.length === 0,
  unexpected.join(", "),
);

console.log("\n[3] every GATED_TOOLS entry is actually registered as a write (schema sanity)");
for (const [name, spec] of Object.entries(GATED_TOOLS)) {
  const t = tools.find((x) => x.name === name);
  check(`${name} is registered`, !!t, "not found in registry");
  check(`${name} is classified as write (no readOnlyHint)`, t && t.annotations?.readOnlyHint !== true, JSON.stringify(t?.annotations));
  check(
    `${name} carries destructiveHint: ${spec.destructive}`,
    t?.annotations?.destructiveHint === spec.destructive,
    JSON.stringify(t?.annotations),
  );
  const props = t?.inputSchema?.properties ?? {};
  check(`${name} schema exposes manifest_id`, "manifest_id" in props, JSON.stringify(Object.keys(props)));
  check(`${name} schema exposes user_reply`, "user_reply" in props, JSON.stringify(Object.keys(props)));
}

console.log("\n[4] behavioural proof: calling each gated tool WITHOUT manifest_id/user_reply never mutates");
for (const [name, spec] of Object.entries(GATED_TOOLS)) {
  const before = spec.counterKey ? counters[spec.counterKey] : null;
  const resp = await cli.callTool({ name, arguments: spec.args });
  const body = text(resp);
  if (spec.counterKey) {
    check(`${name} plan call: mutation counter (${spec.counterKey}) unchanged`, counters[spec.counterKey] === before, String(counters[spec.counterKey]));
  }
  if (spec.planMustNotContain) {
    check(
      `${name} plan call: nothing was handed out (no «${spec.planMustNotContain}» in the plan)`,
      !body.includes(spec.planMustNotContain),
      body.slice(0, 200),
    );
  }
  check(`${name} plan call: response is a plan, not a success/failure header`, body.includes("### 📤 План"), body.slice(0, 60));
  check(`${name} plan call: no ✅/✉️/❌ success-style header`, !/^[✅✉️❌]/.test(body), body.slice(0, 10));
}

console.log("\n[5] read tools genuinely carry readOnlyHint (spot-check, not exhaustive)");
for (const name of ["gmail_list_scheduled_sends", "gmail_confirm_upload", "list_accounts"]) {
  const t = tools.find((x) => x.name === name);
  check(`${name} readOnlyHint: true`, t?.annotations?.readOnlyHint === true, JSON.stringify(t?.annotations));
}

// ── [6] у КАЖДОГО гейтованного тула есть исполнитель для кнопки в Telegram ──
// Иначе получается тихий тупик: человек нажимает «✅ Подтвердить», манифест
// помечается подтверждённым, а исполнять действие некому — поллер в http.ts
// ищет исполнителя в реестре autoExecute.ts по ИМЕНИ тула.
console.log("\n[6] every gated tool has an auto-executor (the Telegram button must lead somewhere)");
const executors = new Set(registeredAutoExecuteTools());
for (const name of Object.keys(GATED_TOOLS)) {
  check(`${name} has an auto-executor`, executors.has(name), [...executors].join(", "));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
