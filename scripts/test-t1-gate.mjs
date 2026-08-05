#!/usr/bin/env node
/**
 * T1 — consent gate wired into the priority-2 write tools (package T1, plan
 * §1 "gmail приоритет-2 под гейт"). Maksim's decision 2026-08-04: ALL write
 * tools go behind the gate, no "it's reversible" exemptions — gmail_archive,
 * gmail_trash, gmail_modify_labels, gmail_create_label, gmail_update_label,
 * gmail_delete_label, gmail_save_attachment_to_drive, gmail_export_thread_eml,
 * gmail_create_upload_session, gmail_create_draft, gmail_snooze.
 *
 * By the same convention as scripts/test-a3-gate.mjs, this drives the REAL
 * registered MCP tools end to end (InMemoryTransport Client/Server pair), not
 * requireConsent() directly. Three representative tools per Maksim's explicit
 * ask, covering the three shapes T1 introduces:
 *  - gmail_trash    — irreversible, existing-object binding (id+subject/from),
 *                     pre-snapshot, post-verify via a fresh label read.
 *  - gmail_create_label — additive, degenerate binding (new resource, same as
 *                     gmail_send), post-verify via a fresh labels.get read.
 *  - gmail_save_attachment_to_drive — additive Drive write, real binding
 *                     (re-reads the source message's MIME tree), post-verify
 *                     via a fresh drive.files.get read.
 *
 * Each gets: plan phase mutates nothing; execute without user_reply is
 * refused; a repeated manifest_id (one-shot) is refused; and the confirmed
 * execute's response carries a §5.3 post-verify report reflecting the fake
 * backend's actual post-mutation state (not just the mutation call's own
 * response).
 *
 * No network, no Postgres — fake in-memory ConsentStore + a small stateful
 * fake Gmail/Drive backend (labels/messages/drive files as in-memory maps
 * that respond to reads AFTER a mutation with the mutation's real effect —
 * i.e. genuinely independent from the mutation call, same spirit as the
 * production postVerify* helpers going back to the live API).
 *
 * Usage: node scripts/test-t1-gate.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};
const parse = (r) => JSON.parse(r.content[0].text);
const text = (r) => r.content[0].text;

function extractManifestId(previewText) {
  const m = previewText.match(/план `([^`]+)`/);
  if (!m) throw new Error("no manifest id found in plan preview: " + previewText);
  return m[1];
}

// ── fake in-memory ConsentStore (same shape as test-a3-gate.mjs) ────────────

function makeConsentStore(clock) {
  const manifests = new Map();
  const audits = new Map();
  return {
    manifests,
    audits,
    async createManifest(input) {
      manifests.set(input.id, { ...input, status: "AWAITING_CONSENT", consumedAt: null, userReply: null });
    },
    async getManifest(id, server) {
      const r = manifests.get(id);
      return r && r.server === server ? { ...r } : null;
    },
    async consumeManifest(id, server, userReply) {
      const r = manifests.get(id);
      if (!r || r.server !== server || r.status !== "AWAITING_CONSENT") return null;
      if (!(r.expiresAt > clock.t)) return null;
      r.status = "DONE";
      r.consumedAt = clock.t;
      r.userReply = userReply;
      return { ...r };
    },
    async invalidateManifest(id, server, userReply) {
      const r = manifests.get(id);
      if (r && r.server === server && r.status === "AWAITING_CONSENT") {
        r.status = "INVALIDATED";
        r.userReply = userReply;
      }
    },
    async appendConsentAudit(entry) {
      audits.set(entry.id, { ...entry });
    },
    async updateConsentAuditOutcome(auditId, outcome) {
      const a = audits.get(auditId);
      if (a) Object.assign(a, outcome);
    },
  };
}

function makeClock(start = 1_700_000_000_000) {
  const c = { t: start };
  return { clock: c, now: () => c.t };
}
function makeCfg(now, overrides = {}) {
  return { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now, ...overrides };
}

// ── fake stateful Gmail/Drive backend ────────────────────────────────────────
//
// Messages/labels/drive-files are in-memory maps that a mutation ACTUALLY
// changes; every subsequent read (including the post-verify helpers' own
// separate reads) sees that real state — so a test asserting "✅ in Trash"
// is asserting the fake genuinely moved the message, not that the tool
// merely claims it did.

function buildState() {
  return {
    messages: new Map([
      ["M1", { subject: "Invoice #42", from: "billing@acme.com", labelIds: new Set(["INBOX", "UNREAD"]) }],
      [
        "M2",
        {
          subject: "Contract draft",
          from: "legal@acme.com",
          labelIds: new Set(["INBOX"]),
          payload: {
            headers: [{ name: "From", value: "legal@acme.com" }, { name: "Subject", value: "Contract draft" }],
            parts: [{ filename: "contract.pdf", mimeType: "application/pdf", body: { attachmentId: "A1", size: 12345 } }],
          },
        },
      ],
    ]),
    labels: new Map(),
    driveFiles: new Map(),
  };
}

function buildClients(counters, state) {
  return {
    names: ["work"],
    defaultName: "work",
    multi: false,
    resolve: () => ({
      gmail: {
        users: {
          getProfile: async () => ({ data: { emailAddress: "me@x.com" } }),
          messages: {
            get: async ({ id, format }) => {
              const m = state.messages.get(id);
              if (!m) throw new Error(`fake: message ${id} not found`);
              const headerPayload = m.payload ?? {
                headers: [{ name: "From", value: m.from }, { name: "Subject", value: m.subject }],
              };
              if (format === "minimal") return { data: { id, labelIds: [...m.labelIds] } };
              return { data: { id, labelIds: [...m.labelIds], payload: headerPayload } };
            },
            modify: async ({ id, requestBody }) => {
              counters.modify++;
              const m = state.messages.get(id);
              for (const l of requestBody.removeLabelIds ?? []) m.labelIds.delete(l);
              for (const l of requestBody.addLabelIds ?? []) m.labelIds.add(l);
              return { data: {} };
            },
            trash: async ({ id }) => {
              counters.trash++;
              const m = state.messages.get(id);
              m.labelIds.delete("INBOX");
              m.labelIds.add("TRASH");
              return { data: {} };
            },
            attachments: {
              get: async () => ({ data: { data: Buffer.from("file-bytes").toString("base64url"), size: 11 } }),
            },
          },
          labels: {
            create: async ({ requestBody }) => {
              counters.labelCreate++;
              const id = "L" + counters.labelCreate;
              state.labels.set(id, { id, name: requestBody.name });
              return { data: { id, name: requestBody.name } };
            },
            get: async ({ id }) => {
              const l = state.labels.get(id);
              if (!l) throw new Error(`fake: label ${id} not found`);
              return { data: { id: l.id, name: l.name } };
            },
            list: async () => ({ data: { labels: [...state.labels.values()] } }),
          },
        },
      },
      drive: {
        files: {
          create: async ({ requestBody }) => {
            counters.driveCreate++;
            const id = "F" + counters.driveCreate;
            state.driveFiles.set(id, { id, name: requestBody.name, trashed: false });
            return { data: { id, name: requestBody.name } };
          },
          get: async ({ fileId }) => {
            const f = state.driveFiles.get(fileId);
            if (!f) throw new Error(`fake: drive file ${fileId} not found`);
            return { data: { id: f.id, name: f.name, trashed: f.trashed } };
          },
        },
      },
    }),
    canonicalName: (n) => (n && n.trim() ? n.trim() : "work"),
    emailFor: () => "me@x.com",
    baseGmailQuery: () => "",
  };
}

function makeCounters() {
  return { modify: 0, trash: 0, labelCreate: 0, driveCreate: 0 };
}

async function harness({ clock, consentCfg } = {}) {
  const counters = makeCounters();
  const state = buildState();
  const clients = buildClients(counters, state);
  const consentStore = makeConsentStore(clock);
  const server = new McpServer({ name: "t1-gate", version: "0" });
  registerGmailTools(server, clients, { store: null, userToken: null, consentStore, consentCfg, auditStore: null });
  const cli = new Client({ name: "c", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), cli.connect(a)]);
  return { cli, counters, consentStore, state };
}

// ═══ gmail_trash — irreversible, existing-object binding ════════════════════

console.log("\n[trash] plan does not mutate");
{
  const { clock, now } = makeClock();
  const { cli, counters, state } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({ name: "gmail_trash", arguments: { messageIds: ["M1"] } });
  check("plan → ### 📤 План", text(plan).includes("### 📤 План"), text(plan).slice(0, 60));
  check("messages.trash NOT called", counters.trash === 0, String(counters.trash));
  check("M1 still has INBOX (untouched)", state.messages.get("M1").labelIds.has("INBOX"));
}

console.log("\n[trash] execute without user_reply → refused, nothing trashed");
{
  const { clock, now } = makeClock();
  const { cli, counters } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({ name: "gmail_trash", arguments: { messageIds: ["M1"] } });
  const manifestId = extractManifestId(text(plan));
  clock.t += 6_000;
  const exec = await cli.callTool({ name: "gmail_trash", arguments: { manifest_id: manifestId } });
  check("refused: нужны оба параметра", text(exec).includes("Нужны оба"), text(exec).slice(0, 80));
  check("nothing trashed", counters.trash === 0, String(counters.trash));
}

console.log("\n[trash] confirmed execute → trashed + post-verify ✅ + one-shot enforced");
{
  const { clock, now } = makeClock();
  const { cli, counters, state } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({ name: "gmail_trash", arguments: { messageIds: ["M1"] } });
  const manifestId = extractManifestId(text(plan));
  clock.t += 6_000;
  const exec = parse(await cli.callTool({ name: "gmail_trash", arguments: { manifest_id: manifestId, user_reply: "да, удаляй" } }));
  check("messages.trash called once", counters.trash === 1, String(counters.trash));
  check("M1 now carries TRASH, not INBOX", state.messages.get("M1").labelIds.has("TRASH") && !state.messages.get("M1").labelIds.has("INBOX"));
  check("summary header ✅/🗑", /^🗑|^✅/.test(exec.summary), exec.summary);
  check("post-verify report present", typeof exec.verification === "string" && exec.verification.includes("🧾"), exec.verification);
  check("post-verify shows ✅ (independently re-read TRASH label)", exec.verification.includes("✅") && exec.verification.includes("Корзине"), exec.verification);
  // Repeat with the SAME manifest_id — one-shot enforced, no second trash call.
  clock.t += 1_000;
  const second = await cli.callTool({ name: "gmail_trash", arguments: { manifest_id: manifestId, user_reply: "да, удаляй" } });
  check("repeated manifest_id refused (one-shot)", !/^🗑|^✅/.test(text(second)), text(second).slice(0, 80));
  check("still only one trash call", counters.trash === 1, String(counters.trash));
}

// ═══ gmail_create_label — additive, degenerate binding ═══════════════════════

console.log("\n[create_label] plan does not mutate");
{
  const { clock, now } = makeClock();
  const { cli, counters } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({ name: "gmail_create_label", arguments: { labels: [{ name: "Vendors/Acme" }] } });
  check("plan → ### 📤 План", text(plan).includes("### 📤 План"), text(plan).slice(0, 60));
  check("labels.create NOT called", counters.labelCreate === 0, String(counters.labelCreate));
}

console.log("\n[create_label] execute without user_reply → refused, nothing created");
{
  const { clock, now } = makeClock();
  const { cli, counters } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({ name: "gmail_create_label", arguments: { labels: [{ name: "Vendors/Acme" }] } });
  const manifestId = extractManifestId(text(plan));
  clock.t += 6_000;
  const exec = await cli.callTool({ name: "gmail_create_label", arguments: { manifest_id: manifestId } });
  check("refused: нужны оба параметра", text(exec).includes("Нужны оба"), text(exec).slice(0, 80));
  check("nothing created", counters.labelCreate === 0, String(counters.labelCreate));
}

console.log("\n[create_label] confirmed execute → created + post-verify ✅ + one-shot enforced");
{
  const { clock, now } = makeClock();
  const { cli, counters, state } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({ name: "gmail_create_label", arguments: { labels: [{ name: "Vendors/Acme" }] } });
  const manifestId = extractManifestId(text(plan));
  clock.t += 6_000;
  const exec = parse(await cli.callTool({ name: "gmail_create_label", arguments: { manifest_id: manifestId, user_reply: "да, создавай" } }));
  check("labels.create called once", counters.labelCreate === 1, String(counters.labelCreate));
  check("label exists in fake backend", [...state.labels.values()].some((l) => l.name === "Vendors/Acme"));
  check("post-verify report present with ✅", exec.verification?.includes("✅"), exec.verification);
  clock.t += 1_000;
  const second = await cli.callTool({ name: "gmail_create_label", arguments: { manifest_id: manifestId, user_reply: "да, создавай" } });
  check("repeated manifest_id refused (one-shot)", !/^🏷️|^✅/.test(text(second)), text(second).slice(0, 80));
  check("still only one label created", counters.labelCreate === 1, String(counters.labelCreate));
}

// ═══ gmail_save_attachment_to_drive — additive Drive write, real binding ════

console.log("\n[save_attachment_to_drive] plan does not mutate");
{
  const { clock, now } = makeClock();
  const { cli, counters } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({
    name: "gmail_save_attachment_to_drive",
    arguments: { items: [{ messageId: "M2", attachmentId: "A1" }] },
  });
  check("plan → ### 📤 План", text(plan).includes("### 📤 План"), text(plan).slice(0, 60));
  check("mentions the real filename (from a live MIME-tree read)", text(plan).includes("contract.pdf"), text(plan));
  check("drive.files.create NOT called", counters.driveCreate === 0, String(counters.driveCreate));
}

console.log("\n[save_attachment_to_drive] execute without user_reply → refused, nothing saved");
{
  const { clock, now } = makeClock();
  const { cli, counters } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({
    name: "gmail_save_attachment_to_drive",
    arguments: { items: [{ messageId: "M2", attachmentId: "A1" }] },
  });
  const manifestId = extractManifestId(text(plan));
  clock.t += 6_000;
  const exec = await cli.callTool({ name: "gmail_save_attachment_to_drive", arguments: { manifest_id: manifestId } });
  check("refused: нужны оба параметра", text(exec).includes("Нужны оба"), text(exec).slice(0, 80));
  check("nothing saved", counters.driveCreate === 0, String(counters.driveCreate));
}

console.log("\n[save_attachment_to_drive] confirmed execute → saved + post-verify ✅ + one-shot enforced");
{
  const { clock, now } = makeClock();
  const { cli, counters, state } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({
    name: "gmail_save_attachment_to_drive",
    arguments: { items: [{ messageId: "M2", attachmentId: "A1" }] },
  });
  const manifestId = extractManifestId(text(plan));
  clock.t += 6_000;
  const exec = parse(
    await cli.callTool({
      name: "gmail_save_attachment_to_drive",
      arguments: { manifest_id: manifestId, user_reply: "да, сохраняй" },
    }),
  );
  check("drive.files.create called once", counters.driveCreate === 1, String(counters.driveCreate));
  check("file exists in fake Drive", state.driveFiles.size === 1);
  check("post-verify report present with ✅", exec.verification?.includes("✅"), exec.verification);
  clock.t += 1_000;
  const second = await cli.callTool({
    name: "gmail_save_attachment_to_drive",
    arguments: { manifest_id: manifestId, user_reply: "да, сохраняй" },
  });
  check("repeated manifest_id refused (one-shot)", !/^💾|^✅/.test(text(second)), text(second).slice(0, 80));
  check("still only one file created", counters.driveCreate === 1, String(counters.driveCreate));
}

// ═══ binding drift: message deleted between plan and trash-execute ══════════

console.log("\n[trash] rehash catches drift — message vanishes between plan and execute");
{
  const { clock, now } = makeClock();
  const { cli, counters, state } = await harness({ clock, consentCfg: makeCfg(now) });
  const plan = await cli.callTool({ name: "gmail_trash", arguments: { messageIds: ["M1"] } });
  const manifestId = extractManifestId(text(plan));
  state.messages.delete("M1"); // simulates the message being gone by execute time
  clock.t += 6_000;
  const exec = await cli.callTool({ name: "gmail_trash", arguments: { manifest_id: manifestId, user_reply: "да, удаляй" } });
  check("refused: состояние изменилось", text(exec).includes("изменилось"), text(exec).slice(0, 100));
  check("nothing trashed", counters.trash === 0, String(counters.trash));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
