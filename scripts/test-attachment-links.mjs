#!/usr/bin/env node
/**
 * Offline check of gmail_get_download_url, gmail_create_upload_session and
 * gmail_confirm_upload.
 *
 * Google is never contacted: the Gmail/Drive clients are stubbed and `fetch` is
 * replaced, so we can assert on the exact upload handshake we send. No
 * credentials, no network, no database — without one, downloads.ts keeps links
 * in memory, which is the path exercised here.
 *
 * Usage:
 *   npm test                             # builds, then runs this
 *   node scripts/test-attachment-links.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools } from "../dist/tools/gmail.js";
import {
  initDownloads,
  downloadsAvailable,
  resolveDownloadLink,
  MAX_TTL_MINUTES,
} from "../dist/downloads.js";

// --- stubs -----------------------------------------------------------------

const calls = [];
let responder = null;

globalThis.fetch = async (url, init = {}) => {
  calls.push({ url: String(url), method: init.method, headers: init.headers ?? {}, body: init.body, redirect: init.redirect });
  return responder(String(url), init);
};

function res({ status = 200, headers = {}, body = "" }) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers[k.toLowerCase()] ?? null },
    text: async () => body,
    json: async () => JSON.parse(body),
  };
}

// A message with one attachment, as Gmail would describe it.
const MESSAGE = {
  id: "MSG1",
  payload: {
    mimeType: "multipart/mixed",
    parts: [
      { mimeType: "text/plain", body: { size: 12 } },
      { filename: "Договор №7.pdf", mimeType: "application/pdf", body: { attachmentId: "ATT1", size: 3_500_000 } },
    ],
  },
};

const driveCalls = [];
let folderListResult = { data: { files: [] } };

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
            return { data: MESSAGE };
          },
          attachments: { get: async () => ({ data: { data: "", size: 0 } }) },
        },
      },
    },
    drive: {
      files: {
        list: async (args) => {
          driveCalls.push({ op: "list", args });
          return folderListResult;
        },
        create: async (args) => {
          driveCalls.push({ op: "create", args });
          const isFolder = args.requestBody?.mimeType === "application/vnd.google-apps.folder";
          return { data: { id: isFolder ? "FOLDER1" : "STAGED1" } };
        },
      },
    },
    docs: {},
    accessToken: async () => "ya29.FAKE",
  }),
  baseGmailQuery: () => "",
};

// gmail_create_upload_session is consent-gated (package T1) — a minimal fake
// ConsentStore + a controllable clock, same shape as scripts/test-a3-gate.mjs,
// so this pre-existing single-call-style test can drive the two-phase
// plan→execute flow instead of expecting an immediate mutation.
const clock = { t: 1_700_000_000_000 };
function makeConsentStore() {
  const manifests = new Map();
  return {
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

const server = new McpServer({ name: "gmail-mcp-test", version: "0" });
registerGmailTools(server, fakeClients, { store: null, userToken: null, consentStore: makeConsentStore(), consentCfg });
const client = new Client({ name: "test-client", version: "0" });
const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
await Promise.all([server.connect(serverSide), client.connect(clientSide)]);

const raw = async (name, args) => client.callTool({ name, arguments: args });
const call = async (name, args) => JSON.parse((await raw(name, args)).content[0].text);

/** Drives gmail_create_upload_session's plan→execute flow in one call, for
 * tests that only care about the mutation's outcome (the gate mechanics
 * themselves are covered by scripts/test-t1-gate.mjs). */
async function planThenExecute(name, args) {
  const planResp = await raw(name, args);
  const planText = planResp.content[0].text;
  const m = planText.match(/план `([^`]+)`/);
  if (!m) throw new Error(`${name}: expected a plan preview, got: ${planText}`);
  clock.t += 6_000; // past MIN_CONSENT_GAP_MS
  return call(name, { manifest_id: m[1], user_reply: "да, давай" });
}

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};

// --- 1. registration --------------------------------------------------------

console.log("\n[1] tool registration");
const names = (await client.listTools()).tools.map((t) => t.name);
for (const t of ["gmail_get_download_url", "gmail_create_upload_session", "gmail_confirm_upload"]) {
  check(`${t} registered`, names.includes(t));
}

// --- 2-5. download links ----------------------------------------------------

console.log("\n[2] no public URL configured");
initDownloads(undefined);
check("downloadsAvailable() is false", downloadsAvailable() === false);
let out = await raw("gmail_get_download_url", { items: [{ messageId: "MSG1", attachmentId: "ATT1" }] });
check("tool refuses with a clear error", out.isError === true && /PUBLIC_BASE_URL/.test(out.content[0].text), out.content[0].text);

console.log("\n[3] link for an attachment, metadata looked up automatically");
initDownloads("https://mail.example.com/");
out = await call("gmail_get_download_url", { items: [{ messageId: "MSG1", attachmentId: "ATT1" }] });
let r = out.results[0];
check("link points at /dl/<token>", /^https:\/\/mail\.example\.com\/dl\/[A-Za-z0-9_-]{20,}$/.test(r.downloadUrl), r.downloadUrl);
check("filename pulled from the message", r.filename === "Договор №7.pdf", r.filename);
check("mime pulled from the message", r.mimeType === "application/pdf", r.mimeType);
check("size pulled from the message", r.bytes === 3_500_000, String(r.bytes));
check("expiry is in the future", new Date(r.expiresAt).getTime() > Date.now(), String(r.expiresAt));

const target = await resolveDownloadLink(r.downloadUrl.split("/dl/")[1]);
check("token resolves to that message + attachment", target?.messageId === "MSG1" && target?.attachmentId === "ATT1", JSON.stringify(target));
check("account recorded for later resolution", target?.account === "personal", String(target?.account));
check("unknown token resolves to null", (await resolveDownloadLink("nope")) === null);

console.log("\n[4] caller-supplied name wins, no message lookup needed");
out = await call("gmail_get_download_url", {
  items: [{ messageId: "MSG404", attachmentId: "ATT1", filename: "custom.bin", mimeType: "application/octet-stream" }],
});
check("no error despite an unknown message id", out.results[0].error === undefined, JSON.stringify(out.results[0]));
check("supplied filename used", out.results[0].filename === "custom.bin", out.results[0].filename);

console.log("\n[5] failures are per item, and TTL is clamped");
out = await call("gmail_get_download_url", {
  items: [{ messageId: "MSG1", attachmentId: "ATT1" }, { messageId: "GHOST", attachmentId: "ATT9" }],
});
check("good item still got a link", typeof out.results[0].downloadUrl === "string", JSON.stringify(out.results[0]));
check("bad item reports its own error", /Message not found/.test(out.results[1].error ?? ""), JSON.stringify(out.results[1]));
check("no link leaked for the bad item", out.results[1].downloadUrl === undefined);
out = await call("gmail_get_download_url", { items: [{ messageId: "MSG1", attachmentId: "ATT1" }], ttlMinutes: MAX_TTL_MINUTES });
const minutes = (new Date(out.results[0].expiresAt).getTime() - Date.now()) / 60000;
check("max TTL honoured", Math.round(minutes) <= MAX_TTL_MINUTES, String(minutes));

// --- 6-8. upload sessions ---------------------------------------------------

console.log("\n[6] upload session — staging folder created on first use");
driveCalls.length = 0;
calls.length = 0;
folderListResult = { data: { files: [] } };
responder = () => res({ status: 200, headers: { location: "https://upload.googleapis.com/?upload_id=S1" } });
out = await planThenExecute("gmail_create_upload_session", {
  files: [{ name: "holiday.mp4", mimeType: "video/mp4", sizeBytes: 20_000_000 }],
});
r = out.results[0];
check("looked for an existing folder first", driveCalls[0].op === "list", driveCalls[0].op);
check("created the staging folder", driveCalls[1].op === "create" && driveCalls[1].args.requestBody.name === "Gmail uploads (staged)", JSON.stringify(driveCalls[1]?.args?.requestBody));
check("placeholder created inside it", driveCalls[2].args.requestBody.parents?.[0] === "FOLDER1", JSON.stringify(driveCalls[2]?.args?.requestBody));
check("placeholder marked as ours", driveCalls[2].args.requestBody.appProperties?.gmailMcpUpload === "1", JSON.stringify(driveCalls[2]?.args?.requestBody?.appProperties));
check("file id returned before any bytes arrive", r.driveFileId === "STAGED1", String(r.driveFileId));
check("uploadUrl returned", r.uploadUrl.includes("upload_id=S1"), r.uploadUrl);
check("session opened with PATCH on the placeholder", calls[0].method === "PATCH" && calls[0].url.includes("/files/STAGED1"), `${calls[0].method} ${calls[0].url}`);
check("X-Upload-Content-Type", calls[0].headers["X-Upload-Content-Type"] === "video/mp4", calls[0].headers["X-Upload-Content-Type"]);
check("X-Upload-Content-Length", calls[0].headers["X-Upload-Content-Length"] === "20000000", calls[0].headers["X-Upload-Content-Length"]);
check("bearer token attached", calls[0].headers.Authorization === "Bearer ya29.FAKE", calls[0].headers.Authorization);
check("tells the model how to attach it", r.thenSend.includes('"driveFileId": "STAGED1"'), r.thenSend);

console.log("\n[7] upload session — existing folder reused, defaults applied");
driveCalls.length = 0;
calls.length = 0;
folderListResult = { data: { files: [{ id: "EXISTING" }] } };
out = await planThenExecute("gmail_create_upload_session", { files: [{ name: "notes.bin" }] });
check("no second folder created", driveCalls.filter((c) => c.op === "create" && c.args.requestBody?.mimeType?.includes("folder")).length === 0);
check("placeholder went into the existing folder", driveCalls[1].args.requestBody.parents?.[0] === "EXISTING", JSON.stringify(driveCalls[1]?.args?.requestBody));
check("defaults to octet-stream", calls[0].headers["X-Upload-Content-Type"] === "application/octet-stream", calls[0].headers["X-Upload-Content-Type"]);
check("no size header when size unknown", calls[0].headers["X-Upload-Content-Length"] === undefined, String(calls[0].headers["X-Upload-Content-Length"]));

console.log("\n[8] upload session — Google refuses");
responder = () => res({ status: 403, body: '{"error":{"message":"storageQuotaExceeded"}}' });
out = await planThenExecute("gmail_create_upload_session", { files: [{ name: "big.bin" }] });
check("HTTP status surfaced", /403/.test(out.results[0].error ?? ""), JSON.stringify(out.results[0]));
responder = () => res({ status: 200 });
out = await planThenExecute("gmail_create_upload_session", { files: [{ name: "x.bin" }] });
check("missing Location reported", /no Location header/.test(out.results[0].error ?? ""), JSON.stringify(out.results[0]));

// --- 9. confirm -------------------------------------------------------------

console.log("\n[9] confirm upload");
// The session URI must now survive the allowlist (see scripts/test-confirm-upload-ssrf.mjs
// for the refusal side) — a bare "https://upload/S1" no longer reaches the network.
const SESSION_URI = "https://www.googleapis.com/upload/drive/v3/files/STAGED1?uploadType=resumable&upload_id=S1";
calls.length = 0;
responder = () => res({ status: 308, headers: { range: "bytes=0-999999" } });
out = await call("gmail_confirm_upload", { uploads: [{ uploadUrl: SESSION_URI, sizeBytes: 20_000_000 }] });
check("status query is a PUT", calls[0].method === "PUT", calls[0].method);
check("Content-Range asks for status", calls[0].headers["Content-Range"] === "bytes */20000000", calls[0].headers["Content-Range"]);
check("redirects are never followed automatically", calls[0].redirect === "manual", String(calls[0].redirect));
check("status = in_progress (308 without Location still works)", out.results[0].status === "in_progress", out.results[0].status);
check("bytesReceived = last + 1", out.results[0].bytesReceived === 1_000_000, String(out.results[0].bytesReceived));

responder = () => res({ status: 200, body: JSON.stringify({ id: "STAGED1", name: "holiday.mp4", size: "20000000" }) });
out = await call("gmail_confirm_upload", { uploads: [{ uploadUrl: SESSION_URI }] });
check("status = complete", out.results[0].status === "complete", out.results[0].status);
check("drive file id returned", out.results[0].driveFileId === "STAGED1", String(out.results[0].driveFileId));

responder = () => res({ status: 410, body: "gone" });
out = await call("gmail_confirm_upload", { uploads: [{ uploadUrl: SESSION_URI }] });
check("410 → expired", out.results[0].status === "expired", out.results[0].status);

responder = () => {
  throw new Error("socket hang up");
};
out = await call("gmail_confirm_upload", { uploads: [{ uploadUrl: SESSION_URI }, { uploadUrl: SESSION_URI }] });
check(
  "network failure contained per session, classified (no raw client error text)",
  out.results.length === 2 && out.results.every((x) => /Не удалось соединиться/.test(x.error ?? "") && !/socket hang up/.test(x.error ?? "")),
  JSON.stringify(out.results),
);

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
