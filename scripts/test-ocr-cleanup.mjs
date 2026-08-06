#!/usr/bin/env node
/**
 * gmail_get_attachment_text — the scratch Google Doc it creates must never be
 * a silent liability (2026-08-06).
 *
 * The tool shipped with NO annotations (so it read as "nothing to see here"),
 * dropped a temp Google Doc into the ROOT of the owner's Drive and then
 * PERMANENTLY deleted it. The delete failure was logged — but the user still
 * got a clean "extracted N/N", so the person whose Drive was collecting
 * "gmcp-ocr-tmp" garbage never heard about it. Four things had to change, and
 * this file is what keeps them changed:
 *
 *  [1] the scratch doc is TRASHED, never files.delete — irreversible deletion
 *      must not be a side effect of reading text;
 *  [2] an identity guard re-reads the file first and refuses to touch anything
 *      that is not our own "gmcp-ocr-tmp" Google Doc;
 *  [3] a cleanup that fails is REPORTED in the tool's own result (id + reason);
 *  [4] the tool declares itself a write (no readOnlyHint) and says in its
 *      description that a temp file lands in the user's Drive.
 *
 * Usage: node scripts/test-ocr-cleanup.mjs
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
const parse = (r) => r.structuredContent ?? JSON.parse(r.content[0].text);

const TEMP_NAME = "gmcp-ocr-tmp";
const GOOGLE_DOC_MIME = "application/vnd.google-apps.document";

/**
 * @param opts.metaOverride  what files.get answers for the scratch id (used to
 *                           fake "this id points at somebody else's file")
 * @param opts.updateThrows  make the trashing call fail
 */
async function buildHarness(opts = {}) {
  const calls = { create: 0, get: 0, update: [], delete: 0 };
  const clients = {
    names: ["work"],
    defaultName: "work",
    multi: false,
    canonicalName: (n) => (n && n.trim() ? n.trim() : "work"),
    emailFor: () => "me@x.com",
    baseGmailQuery: () => "",
    resolve: () => ({
      gmail: {
        users: {
          getProfile: async () => ({ data: { emailAddress: "me@x.com" } }),
          messages: {
            attachments: {
              get: async () => ({ data: { data: Buffer.from("%PDF-1.4 fake").toString("base64url"), size: 12 } }),
            },
          },
        },
      },
      drive: {
        files: {
          create: async () => {
            calls.create++;
            return { data: { id: "TMPDOC1" } };
          },
          get: async ({ fileId }) => {
            calls.get++;
            return {
              data: opts.metaOverride ?? { id: fileId, name: TEMP_NAME, mimeType: GOOGLE_DOC_MIME, trashed: false },
            };
          },
          update: async (args) => {
            calls.update.push(args);
            if (opts.updateThrows) throw new Error("Drive said 403: insufficient permissions");
            return { data: { id: args.fileId, trashed: true } };
          },
          // Kept ONLY so an accidental permanent delete would be recorded and
          // fail the test below — the tool must never reach it.
          delete: async () => {
            calls.delete++;
          },
        },
      },
      docs: {
        documents: {
          get: async ({ documentId }) => ({
            data: {
              documentId,
              title: TEMP_NAME,
              body: { content: [{ endIndex: 12, paragraph: { elements: [{ textRun: { content: "INVOICE 42\n" } }] } }] },
            },
          }),
        },
      },
      accessToken: async () => "fake-token",
    }),
  };
  const server = new McpServer({ name: "ocr-cleanup", version: "0" });
  registerGmailTools(server, clients, {
    store: null,
    userToken: null,
    consentStore: {
      async createManifest() {},
      async getManifest() {
        return null;
      },
      async consumeManifest() {
        return null;
      },
      async invalidateManifest() {},
      async appendConsentAudit() {},
      async updateConsentAuditOutcome() {},
    },
    consentCfg: { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 0, sendBatchMax: 10 },
  });
  const cli = new Client({ name: "c", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), cli.connect(a)]);
  return { cli, calls };
}

const ARGS = { items: [{ messageId: "M1", attachmentId: "ATT1", mimeType: "application/pdf" }] };

// ── [1] happy path: text comes back, scratch doc is TRASHED, never deleted ──

console.log("\n[1] happy path — the scratch doc is trashed, not permanently deleted");
{
  const { cli, calls } = await buildHarness();
  const out = parse(await cli.callTool({ name: "gmail_get_attachment_text", arguments: ARGS }));
  check("OCR text returned", out.results[0].text.includes("INVOICE 42"), JSON.stringify(out.results[0]));
  check("a scratch doc was created", calls.create === 1, String(calls.create));
  check("cleanup went through files.update(trashed:true)", calls.update.length === 1 && calls.update[0].requestBody?.trashed === true, JSON.stringify(calls.update));
  check("files.delete was NEVER called (no permanent deletion)", calls.delete === 0, String(calls.delete));
  check("no leftover warning on a clean run", !("warning" in out) && !("leftoverTempFiles" in out), JSON.stringify(Object.keys(out)));
}

// ── [2] the point of the whole exercise: a FAILED cleanup must be reported ──

console.log("\n[2] cleanup failure is REPORTED to the caller, not just logged");
{
  const { cli, calls } = await buildHarness({ updateThrows: true });
  const out = parse(await cli.callTool({ name: "gmail_get_attachment_text", arguments: ARGS }));
  check("the text still comes back (cleanup failure is not fatal)", out.results[0].text.includes("INVOICE 42"), JSON.stringify(out.results[0]));
  check("result carries a warning", typeof out.warning === "string" && out.warning.length > 0, JSON.stringify(out.warning));
  check("the warning names the leftover file id", (out.warning ?? "").includes("TMPDOC1"), JSON.stringify(out.warning));
  check("leftoverTempFiles lists the id", out.leftoverTempFiles?.[0]?.tempFileId === "TMPDOC1", JSON.stringify(out.leftoverTempFiles));
  check("leftoverTempFiles carries the real reason", /403/.test(out.leftoverTempFiles?.[0]?.error ?? ""), JSON.stringify(out.leftoverTempFiles));
  check(
    "the summary is NOT a clean 'extracted 1/1' with the failure hidden elsewhere",
    JSON.stringify(out).includes("could NOT be cleaned up"),
    JSON.stringify(out.summary),
  );
  check("still no permanent delete attempted", calls.delete === 0, String(calls.delete));
}

// ── [3] identity guard: never touch a file that is not our scratch doc ──────

console.log("\n[3] identity guard — a foreign file is left alone and reported");
{
  const { cli, calls } = await buildHarness({
    metaOverride: { id: "TMPDOC1", name: "Договор аренды.pdf", mimeType: "application/pdf", trashed: false },
  });
  const out = parse(await cli.callTool({ name: "gmail_get_attachment_text", arguments: ARGS }));
  check("the foreign file was NOT trashed", calls.update.length === 0, JSON.stringify(calls.update));
  check("the foreign file was NOT deleted", calls.delete === 0, String(calls.delete));
  check("the mismatch is reported", /identity guard/.test(out.leftoverTempFiles?.[0]?.error ?? ""), JSON.stringify(out.leftoverTempFiles));
  check("the report names the file it refused to touch", /Договор аренды\.pdf/.test(out.leftoverTempFiles?.[0]?.error ?? ""), JSON.stringify(out.leftoverTempFiles));
}

// ── [4] an already-trashed scratch doc is not touched again, and is not news ─

console.log("\n[4] an already-trashed scratch doc needs no second trashing and no warning");
{
  const { cli, calls } = await buildHarness({
    metaOverride: { id: "TMPDOC1", name: TEMP_NAME, mimeType: GOOGLE_DOC_MIME, trashed: true },
  });
  const out = parse(await cli.callTool({ name: "gmail_get_attachment_text", arguments: ARGS }));
  check("no redundant update call", calls.update.length === 0, JSON.stringify(calls.update));
  check("no warning (nothing is actually left behind)", !("warning" in out), JSON.stringify(out.warning));
}

// ── [5] the annotation must not undo the fix ────────────────────────────────

console.log("\n[5] the tool declares itself a write");
{
  const { cli } = await buildHarness();
  const t = (await cli.listTools()).tools.find((x) => x.name === "gmail_get_attachment_text");
  check("gmail_get_attachment_text is registered", !!t);
  check("does NOT claim readOnlyHint (it creates and trashes a real file)", t?.annotations?.readOnlyHint !== true, JSON.stringify(t?.annotations));
  check("carries an explicit destructiveHint: false (reversible — trash)", t?.annotations?.destructiveHint === false, JSON.stringify(t?.annotations));
  check("description warns that a temp file lands in the user's Drive", /temporary Google Doc/i.test(t?.description ?? ""), (t?.description ?? "").slice(0, 160));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
