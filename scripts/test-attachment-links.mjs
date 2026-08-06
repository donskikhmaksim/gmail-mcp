#!/usr/bin/env node
/**
 * Offline check of gmail_get_download_url, gmail_create_upload_session and
 * gmail_confirm_upload.
 *
 * Google is never contacted: the Gmail/Drive clients are stubbed and the
 * outbound HTTP transport is INJECTED (`safeFetch` in the registration
 * context — production never passes it), so we can assert on the exact upload
 * handshake we send. No credentials, no network, no database — without one,
 * downloads.ts/uploadSessions.ts keep records in memory, which is the path
 * exercised here.
 *
 * ЧТО ЗДЕСЬ ЗАКРЫВАЕТСЯ ПОМИМО СТАРОГО ПОВЕДЕНИЯ (две дыры, найденные
 * аудитом):
 *  - `gmail_get_download_url` больше НЕ «только чтение»: ссылка сама является
 *    доступом (кто её получил — скачает вложение без входа, отозвать нельзя),
 *    поэтому тул проведён через гейт подтверждения. Блок [3a] проверяет, что
 *    ФАЗА ПЛАНА не выдаёт ни одной ссылки, а текст над кнопкой говорит
 *    правду: «скачает любой», «отозвать нельзя», конкретный срок.
 *  - `gmail_confirm_upload` больше НЕ принимает адрес аргументом: он получает
 *    непрозрачный `sessionId`, а реальный адрес берёт из своего хранилища —
 *    подделать «сходи на 169.254.169.254» через аргумент физически нечем
 *    (блок [9a]).
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

/** Injected transport: replaces the real undici fetch inside safeGoogleFetch. */
const fetchImpl = async (url, init = {}) => {
  calls.push({
    url: String(url),
    method: init.method,
    headers: init.headers ?? {},
    body: init.body,
    redirect: init.redirect,
  });
  return responder(String(url), init);
};
/** Injected resolver: googleapis.com "resolves" to a public address, so the
 * private-address guard passes without touching real DNS. */
const lookup = async () => [{ address: "142.250.72.1" }];
const safeFetch = { fetchImpl, lookup };

function res({ status = 200, headers = {}, body = "" }) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers[k.toLowerCase()] ?? null },
    text: async () => body,
    json: async () => JSON.parse(body),
  };
}

/** Session URIs Google really hands back live on googleapis.com — the guard in
 * src/safeFetch.ts only accepts those, so the stubs use realistic ones. */
const SESSION_URI = (id) => `https://www.googleapis.com/upload/drive/v3/files/STAGED1?upload_id=${id}`;

// A message with one attachment, as Gmail would describe it.
const MESSAGE = {
  id: "MSG1",
  payload: {
    mimeType: "multipart/mixed",
    headers: [
      { name: "From", value: "eric@x.com" },
      { name: "Subject", value: "Договор" },
    ],
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
        get: async ({ fileId }) => ({ data: { id: fileId, name: "staged", trashed: false } }),
      },
    },
    docs: {},
    accessToken: async () => "ya29.FAKE",
  }),
  baseGmailQuery: () => "",
};

// gmail_create_upload_session AND gmail_get_download_url are consent-gated — a
// minimal fake ConsentStore + a controllable clock, same shape as
// scripts/test-a3-gate.mjs, so these single-call-style tests can drive the
// two-phase plan→execute flow.
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
registerGmailTools(server, fakeClients, {
  store: null,
  userToken: null,
  consentStore: makeConsentStore(),
  consentCfg,
  safeFetch,
});
const client = new Client({ name: "test-client", version: "0" });
const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
await Promise.all([server.connect(serverSide), client.connect(clientSide)]);

const raw = async (name, args) => client.callTool({ name, arguments: args });
const call = async (name, args) => JSON.parse((await raw(name, args)).content[0].text);

/** Drives a gated tool's plan→execute flow in one call, for tests that only
 * care about the mutation's outcome (the gate mechanics themselves are covered
 * by scripts/test-t1-gate.mjs). Returns the parsed execute-call result. */
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
const tools = (await client.listTools()).tools;
const names = tools.map((t) => t.name);
for (const t of ["gmail_get_download_url", "gmail_create_upload_session", "gmail_confirm_upload"]) {
  check(`${t} registered`, names.includes(t));
}

// --- 2-5. download links ----------------------------------------------------

console.log("\n[2] no public URL configured");
initDownloads(undefined);
check("downloadsAvailable() is false", downloadsAvailable() === false);
let out = await raw("gmail_get_download_url", { items: [{ messageId: "MSG1", attachmentId: "ATT1" }] });
check("tool refuses with a clear error", out.isError === true && /PUBLIC_BASE_URL/.test(out.content[0].text), out.content[0].text);

// ── [3a] THE GATE ITSELF: a plan call issues nothing, and says so honestly ──
console.log("\n[3a] gmail_get_download_url is gated — the plan call hands out NO link");
initDownloads("https://mail.example.com/");
const dl = tools.find((t) => t.name === "gmail_get_download_url");
check("NOT advertised as read-only (the link IS access, not a read)", dl?.annotations?.readOnlyHint !== true, JSON.stringify(dl?.annotations));
check("schema exposes manifest_id", "manifest_id" in (dl?.inputSchema?.properties ?? {}), JSON.stringify(Object.keys(dl?.inputSchema?.properties ?? {})));
check("schema exposes user_reply", "user_reply" in (dl?.inputSchema?.properties ?? {}), JSON.stringify(Object.keys(dl?.inputSchema?.properties ?? {})));

const planResp = await raw("gmail_get_download_url", { items: [{ messageId: "MSG1", attachmentId: "ATT1" }] });
const planText = planResp.content[0].text;
check("plan phase returns a plan, not a result", planText.includes("### 📤 План"), planText.slice(0, 60));
check("plan phase leaked NO link", !/\/dl\//.test(planText), planText.slice(0, 200));
// The consent text must describe what actually happens — a person confirms
// what they understood, so "получить ссылку" would be a lie of omission.
check("consent text: anyone holding it can download", /скачает файл БЕЗ входа|любой, у кого она/i.test(planText), planText.slice(0, 400));
check("consent text: cannot be revoked", /отозвать[^.]{0,40}нельзя/i.test(planText), planText.slice(0, 400));
check("consent text: states how long it lives", /\d+\s*мин/.test(planText), planText.slice(0, 400));
check("consent text: spells out what the button does", /Кнопка «✅ Подтвердить» означает/.test(planText), planText.slice(-300));

console.log("\n[3] link for an attachment, metadata looked up automatically");
out = await planThenExecute("gmail_get_download_url", { items: [{ messageId: "MSG1", attachmentId: "ATT1" }] });
let r = out.results[0];
check("link points at /dl/<token>", /^https:\/\/mail\.example\.com\/dl\/[A-Za-z0-9_-]{20,}$/.test(r.downloadUrl), r.downloadUrl);
check("filename pulled from the message", r.filename === "Договор №7.pdf", r.filename);
check("mime pulled from the message", r.mimeType === "application/pdf", r.mimeType);
check("size pulled from the message", r.bytes === 3_500_000, String(r.bytes));
check("expiry is in the future", new Date(r.expiresAt).getTime() > Date.now(), String(r.expiresAt));
check("post-verify report attached", /Независимая проверка выданных ссылок/.test(JSON.stringify(out)), JSON.stringify(out).slice(0, 200));

const target = await resolveDownloadLink(r.downloadUrl.split("/dl/")[1]);
check("token resolves to that message + attachment", target?.messageId === "MSG1" && target?.attachmentId === "ATT1", JSON.stringify(target));
check("account recorded for later resolution", target?.account === "personal", String(target?.account));
check("unknown token resolves to null", (await resolveDownloadLink("nope")) === null);

console.log("\n[4] caller-supplied name wins, no message lookup needed");
out = await planThenExecute("gmail_get_download_url", {
  items: [{ messageId: "MSG404", attachmentId: "ATT1", filename: "custom.bin", mimeType: "application/octet-stream" }],
});
check("no error despite an unknown message id", out.results[0].error === undefined, JSON.stringify(out.results[0]));
check("supplied filename used", out.results[0].filename === "custom.bin", out.results[0].filename);

console.log("\n[5] failures are per item, and TTL is clamped");
out = await planThenExecute("gmail_get_download_url", {
  items: [{ messageId: "MSG1", attachmentId: "ATT1" }, { messageId: "GHOST", attachmentId: "ATT9" }],
});
check("good item still got a link", typeof out.results[0].downloadUrl === "string", JSON.stringify(out.results[0]));
check("bad item reports its own error", /Message not found/.test(out.results[1].error ?? ""), JSON.stringify(out.results[1]));
check("no link leaked for the bad item", out.results[1].downloadUrl === undefined);
out = await planThenExecute("gmail_get_download_url", { items: [{ messageId: "MSG1", attachmentId: "ATT1" }], ttlMinutes: MAX_TTL_MINUTES });
const minutes = (new Date(out.results[0].expiresAt).getTime() - Date.now()) / 60000;
check("max TTL honoured", Math.round(minutes) <= MAX_TTL_MINUTES, String(minutes));

// --- 6-8. upload sessions ---------------------------------------------------

console.log("\n[6] upload session — staging folder created on first use");
driveCalls.length = 0;
calls.length = 0;
folderListResult = { data: { files: [] } };
responder = () => res({ status: 200, headers: { location: SESSION_URI("S1") } });
out = await planThenExecute("gmail_create_upload_session", {
  files: [{ name: "holiday.mp4", mimeType: "video/mp4", sizeBytes: 20_000_000 }],
});
r = out.results[0];
check("looked for an existing folder first", driveCalls[0].op === "list", driveCalls[0].op);
check("created the staging folder", driveCalls[1].op === "create" && driveCalls[1].args.requestBody.name === "Gmail uploads (staged)", JSON.stringify(driveCalls[1]?.args?.requestBody));
check("placeholder created inside it", driveCalls[2].args.requestBody.parents?.[0] === "FOLDER1", JSON.stringify(driveCalls[2]?.args?.requestBody));
check("placeholder marked as ours", driveCalls[2].args.requestBody.appProperties?.gmailMcpUpload === "1", JSON.stringify(driveCalls[2]?.args?.requestBody?.appProperties));
check("file id returned before any bytes arrive", r.driveFileId === "STAGED1", String(r.driveFileId));
check("uploadUrl returned to the caller (client PUTs the bytes there)", r.uploadUrl.includes("upload_id=S1"), r.uploadUrl);
check("opaque sessionId returned alongside it", typeof r.sessionId === "string" && r.sessionId.length >= 20, String(r.sessionId));
check("sessionId is NOT the address", !String(r.sessionId).includes("://"), String(r.sessionId));
check("howTo points at sessionId, not the URL", /sessionId/.test(r.howTo ?? ""), String(r.howTo));
check("session opened with PATCH on the placeholder", calls[0].method === "PATCH" && calls[0].url.includes("/files/STAGED1"), `${calls[0].method} ${calls[0].url}`);
check("X-Upload-Content-Type", calls[0].headers["X-Upload-Content-Type"] === "video/mp4", calls[0].headers["X-Upload-Content-Type"]);
check("X-Upload-Content-Length", calls[0].headers["X-Upload-Content-Length"] === "20000000", calls[0].headers["X-Upload-Content-Length"]);
check("bearer token attached", calls[0].headers.Authorization === "Bearer ya29.FAKE", calls[0].headers.Authorization);
check("redirects are never followed blindly (redirect: manual)", calls[0].redirect === "manual", String(calls[0].redirect));
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

console.log("\n[8b] upload session — Location points somewhere it must not");
for (const bad of ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:1/x", "https://evil.example/x"]) {
  responder = () => res({ status: 200, headers: { location: bad } });
  out = await planThenExecute("gmail_create_upload_session", { files: [{ name: "x.bin" }] });
  check(`Location ${bad} refused`, /недопустимый адрес/.test(out.results[0].error ?? ""), JSON.stringify(out.results[0]));
  check(`Location ${bad}: no sessionId handed out`, out.results[0].sessionId === undefined, String(out.results[0].sessionId));
}

/** Opens one session through the gate and returns its opaque sessionId. */
async function newSession(name = "file.bin", id = "S-DEFAULT") {
  responder = () => res({ status: 200, headers: { location: SESSION_URI(id) } });
  const o = await planThenExecute("gmail_create_upload_session", { files: [{ name }] });
  const sid = o.results[0].sessionId;
  if (!sid) throw new Error(`no sessionId in ${JSON.stringify(o.results[0])}`);
  return sid;
}

// --- 9. confirm -------------------------------------------------------------

console.log("\n[9] confirm upload — addressed by the opaque sessionId");
const s1 = await newSession("holiday.mp4", "S1");
calls.length = 0;
responder = () => res({ status: 308, headers: { range: "bytes=0-999999" } });
out = await call("gmail_confirm_upload", { uploads: [{ sessionId: s1, sizeBytes: 20_000_000 }] });
check("status query is a PUT", calls[0].method === "PUT", calls[0].method);
check("goes to the address the SERVER stored, not one from the model", calls[0].url.includes("upload_id=S1"), calls[0].url);
check("Content-Range asks for status", calls[0].headers["Content-Range"] === "bytes */20000000", calls[0].headers["Content-Range"]);
check("status = in_progress", out.results[0].status === "in_progress", out.results[0].status);
check("bytesReceived = last + 1", out.results[0].bytesReceived === 1_000_000, String(out.results[0].bytesReceived));
check("result is addressed by sessionId, the URL is not echoed back", out.results[0].sessionId === s1 && out.results[0].uploadUrl === undefined, JSON.stringify(out.results[0]));

// ── [9a] THE SSRF FIX: an address from the model is not accepted at all ─────
console.log("\n[9a] gmail_confirm_upload refuses to take an ADDRESS from the model");
const confirm = tools.find((t) => t.name === "gmail_confirm_upload");
const uploadProps = confirm?.inputSchema?.properties?.uploads?.items?.properties ?? {};
check("schema has NO uploadUrl field at all", !("uploadUrl" in uploadProps), JSON.stringify(Object.keys(uploadProps)));
check("schema takes sessionId instead", "sessionId" in uploadProps, JSON.stringify(Object.keys(uploadProps)));
calls.length = 0;
const badCall = await raw("gmail_confirm_upload", { uploads: [{ uploadUrl: "http://169.254.169.254/latest/meta-data/" }] });
check("call carrying only uploadUrl is rejected outright", badCall.isError === true, JSON.stringify(badCall).slice(0, 200));
check("…and nothing was fetched", calls.length === 0, String(calls.length));
calls.length = 0;
out = await call("gmail_confirm_upload", { uploads: [{ sessionId: "http://169.254.169.254/latest/meta-data/" }] });
check("an ADDRESS passed as a sessionId is just an unknown session", /не найдена/.test(out.results[0].error ?? ""), JSON.stringify(out.results[0]));
check("…and still nothing was fetched", calls.length === 0, String(calls.length));

console.log("\n[10] confirm upload — finished / expired / network failure");
const s2 = await newSession("holiday.mp4", "S2");
responder = () => res({ status: 200, body: JSON.stringify({ id: "STAGED1", name: "holiday.mp4", size: "20000000" }) });
out = await call("gmail_confirm_upload", { uploads: [{ sessionId: s2 }] });
check("status = complete", out.results[0].status === "complete", out.results[0].status);
check("drive file id returned", out.results[0].driveFileId === "STAGED1", String(out.results[0].driveFileId));

const s3 = await newSession("holiday.mp4", "S3");
responder = () => res({ status: 410, body: "gone" });
out = await call("gmail_confirm_upload", { uploads: [{ sessionId: s3 }] });
check("410 → expired", out.results[0].status === "expired", out.results[0].status);

const s4 = await newSession("a.bin", "S4");
const s5 = await newSession("b.bin", "S5");
responder = () => {
  throw new Error("socket hang up");
};
out = await call("gmail_confirm_upload", { uploads: [{ sessionId: s4 }, { sessionId: s5 }] });
check(
  "network failure contained per session",
  out.results.length === 2 && out.results.every((x) => /socket hang up/.test(x.error ?? "")),
  JSON.stringify(out.results),
);

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
