#!/usr/bin/env node
/**
 * Consent gate on `gmail_get_download_url`.
 *
 * This tool does not touch the mailbox — it MINTS A CAPABILITY: an
 * unauthenticated link that hands one attachment's bytes to whoever holds it,
 * for up to 12 hours, with no way to revoke it. Before this change it did that
 * with no confirmation at all while carrying `readOnlyHint: true`. The sibling
 * repo gates the equivalent action (drive_share), so it is gated the same way
 * here: plan → show the human → execute with their verbatim reply.
 *
 * Covered (`references/testing-deploy.md` §13): happy path, every refusal path
 * (no user_reply / negative reply / replayed manifest), and the binding —
 * the attachment drifting between plan and confirmation must refuse instead of
 * minting a link for whatever is there now. Every refusal asserts ZERO links
 * were issued (nothing landed in the token store).
 *
 * No network, no Postgres: fake ConsentStore + fake Gmail client + downloads.ts
 * running on its in-memory token store.
 *
 * Usage: node scripts/test-download-url-gate.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";
import { initDownloads, resolveDownloadLink } from "../dist/downloads.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};

const clock = { t: 1_700_000_000_000 };

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
    async appendConsentAudit() {},
    async updateConsentAuditOutcome() {},
  };
}
const consentCfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now: () => clock.t };

// A message with one attachment; `size` is mutable so a test can make the
// attachment drift between plan and confirmation.
const attachment = { filename: "Договор №7.pdf", mimeType: "application/pdf", size: 3_500_000 };
const fakeClients = {
  names: ["personal"],
  defaultName: "personal",
  multi: false,
  canonicalName: (n) => (n && n.trim() ? n.trim() : "personal"),
  emailFor: () => "me@personal.test",
  resolve: () => ({
    gmail: {
      users: {
        messages: {
          get: async ({ id }) => {
            if (id !== "MSG1") throw new Error(`Message not found: ${id}`);
            return {
              data: {
                id,
                payload: {
                  mimeType: "multipart/mixed",
                  headers: [
                    { name: "From", value: "eric@x.com" },
                    { name: "Subject", value: "Договор" },
                  ],
                  parts: [
                    { mimeType: "text/plain", body: { size: 10 } },
                    {
                      filename: attachment.filename,
                      mimeType: attachment.mimeType,
                      body: { attachmentId: "ATT1", size: attachment.size },
                    },
                  ],
                },
              },
            };
          },
        },
      },
    },
    drive: { files: {} },
    docs: {},
    accessToken: async () => "ya29.FAKE",
  }),
  baseGmailQuery: () => "",
};

initDownloads("https://mail.example.test");

const server = new McpServer({ name: "download-url-gate", version: "0" });
registerGmailTools(server, fakeClients, {
  store: null,
  userToken: null,
  consentStore: makeConsentStore(),
  consentCfg,
});
const client = new Client({ name: "c", version: "0" });
const [a, b] = InMemoryTransport.createLinkedPair();
await Promise.all([server.connect(b), client.connect(a)]);

const call = async (args) => {
  const r = await client.callTool({ name: "gmail_get_download_url", arguments: args });
  return { isError: r.isError === true, text: r.content[0].text, data: r.structuredContent };
};
const manifestIdOf = (previewText) => {
  const m = previewText.match(/план `([^`]+)`/);
  if (!m) throw new Error("no manifest id in preview: " + previewText);
  return m[1];
};
const linksIn = (text) => (text.match(/\/dl\/[A-Za-z0-9_-]+/g) ?? []).length;

const ITEMS = [{ messageId: "MSG1", attachmentId: "ATT1" }];

// ── 1. plan phase mints nothing ─────────────────────────────────────────────

console.log("\n[1] plan phase");
const plan1 = await call({ items: ITEMS });
check("returns a plan", plan1.text.includes("### 📤 План: Выдать ссылки на вложения"), plan1.text.slice(0, 80));
check("no link was issued", linksIn(plan1.text) === 0, plan1.text.slice(0, 120));
check("preview names the file and the message it came from", /Договор №7\.pdf/.test(plan1.text) && /Договор/.test(plan1.text) && /eric@x\.com/.test(plan1.text), plan1.text.slice(0, 300));
check("preview spells out that the link needs no sign-in", /скачает файл БЕЗ входа/.test(plan1.text), plan1.text);
check("preview states the lifetime and that it cannot be revoked", /30 мин/.test(plan1.text) && /Отозвать выданную ссылку нельзя/.test(plan1.text), plan1.text);

// ── 2. refusal paths ────────────────────────────────────────────────────────

console.log("\n[2] refusals — nothing is ever handed out");
{
  const id = manifestIdOf(plan1.text);
  clock.t += 6_000;

  const noReply = await call({ manifest_id: id, items: ITEMS });
  check("manifest_id without user_reply → not executed", linksIn(noReply.text) === 0, noReply.text.slice(0, 160));

  const negative = await call({ manifest_id: id, user_reply: "нет, отмена" });
  check("negative reply refused", /🛑/.test(negative.text), negative.text.slice(0, 160));
  check("negative reply issued no link", linksIn(negative.text) === 0, negative.text.slice(0, 160));

  const afterInvalidation = await call({ manifest_id: id, user_reply: "да, давай" });
  check("a refused manifest is dead, not retryable", linksIn(afterInvalidation.text) === 0, afterInvalidation.text.slice(0, 160));
}

// ── 3. happy path + post-verify + one-shot ──────────────────────────────────

console.log("\n[3] happy path");
let issuedToken = null;
{
  const plan = await call({ items: ITEMS });
  const id = manifestIdOf(plan.text);
  clock.t += 6_000;
  const done = await call({ manifest_id: id, user_reply: "да, давай" });
  const body = done.data;
  check("one link issued", linksIn(done.text) === 1, done.text.slice(0, 200));
  check("summary is the server's own status line", /^🔗 Выдано ссылок: 1\/1/.test(body.summary), body.summary);
  check("post-verify report attached", /Независимая проверка выданных ссылок/.test(body.verification ?? ""), String(body.verification).slice(0, 80));
  check("post-verify says the token resolves to this attachment", /✅/.test(body.verification ?? ""), String(body.verification).slice(0, 200));
  issuedToken = body.results[0].downloadUrl.split("/dl/")[1];
  const rec = await resolveDownloadLink(issuedToken);
  check("token really is in the store, pointing at MSG1/ATT1", rec?.messageId === "MSG1" && rec?.attachmentId === "ATT1", JSON.stringify(rec));

  const replay = await call({ manifest_id: id, user_reply: "да, давай" });
  check("replaying the manifest is refused (one-shot)", /🛑/.test(replay.text), replay.text.slice(0, 160));
  check("replay issued no second link", linksIn(replay.text) === 0, replay.text.slice(0, 160));
}

// ── 4. binding: the attachment drifting after the plan refuses ──────────────

console.log("\n[4] binding — a changed attachment does not inherit the consent");
{
  const plan = await call({ items: ITEMS });
  const id = manifestIdOf(plan.text);
  clock.t += 6_000;
  const originalSize = attachment.size;
  attachment.size = 9_999_999; // same attachmentId, different file behind it
  const drifted = await call({ manifest_id: id, user_reply: "да, давай" });
  attachment.size = originalSize;
  check("drift refused", /🛑/.test(drifted.text), drifted.text.slice(0, 200));
  check("drift issued no link", linksIn(drifted.text) === 0, drifted.text.slice(0, 200));
}

// ── 5. a TTL above the hard maximum is rejected by the schema ───────────────

console.log("\n[5] TTL cap");
{
  const over = await call({ items: ITEMS, ttlMinutes: 13 * 60 });
  check("ttlMinutes beyond MAX is refused outright", over.isError === true, over.text.slice(0, 160));
  check("no link issued", linksIn(over.text) === 0, over.text.slice(0, 160));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
