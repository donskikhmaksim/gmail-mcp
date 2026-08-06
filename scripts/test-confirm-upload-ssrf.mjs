#!/usr/bin/env node
/**
 * SSRF guard for `gmail_confirm_upload` (src/tools/gmail.ts).
 *
 * The tool PUTs to a URL that comes STRAIGHT FROM THE MODEL, on a server whose
 * whole job is reading mail written by strangers — i.e. the address can be
 * planted by someone else's email text. Before this fix the URL was a bare
 * `z.string()` and up to 500 bytes of the answer's body were echoed back into
 * the tool result: a read-anything-reachable primitive with its own
 * exfiltration channel attached.
 *
 * Covered here (`references/security-checklist.md` §2 + §6):
 *  1. `assertGoogleUploadUrl` — the allowlist itself, unit level: scheme,
 *     credentials, port, host (EXACT match / real subdomain, never substring),
 *     path prefix derived from DRIVE_UPLOAD_ENDPOINT.
 *  2. the tool end to end through a REAL MCP server + client pair: every
 *     refusal makes ZERO outbound requests (fetch counter stays at 0), and an
 *     unexpected upstream answer never leaks its body into the result.
 *
 * No network: `globalThis.fetch` is replaced with a counting stub (the tool
 * uses the global fetch, unlike the attachment path which uses undici's own).
 *
 * Usage: node scripts/test-confirm-upload-ssrf.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerGmailTools, assertGoogleUploadUrl } from "../dist/tools/gmail.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};

// ── 1. the allowlist helper, called directly ────────────────────────────────

function refused(label, url) {
  let threw = false;
  let msg = "";
  try {
    assertGoogleUploadUrl(url);
  } catch (e) {
    threw = true;
    msg = e instanceof Error ? e.message : String(e);
  }
  check(`refused: ${label}`, threw && msg.startsWith("🛑"), threw ? msg : "did NOT throw");
}

console.log("\n[1] assertGoogleUploadUrl — allowlist by URL structure, never by substring");

// The decoys the old "does it contain googleapis.com" style of check lets through.
refused("path decoy https://evil.example.com/googleapis.com/upload", "https://evil.example.com/googleapis.com/upload");
refused("suffix decoy https://googleapis.com.evil.com/…", "https://googleapis.com.evil.com/upload/drive/v3/files");
refused("prefix decoy https://evil-googleapis.com/…", "https://evil-googleapis.com/upload/drive/v3/files");
refused("subdomain-of-attacker decoy", "https://www.googleapis.com.attacker.test/upload/drive/v3/files");
refused("userinfo decoy https://www.googleapis.com@evil.test/…", "https://www.googleapis.com@evil.test/upload/drive/v3/files");

// Scheme / credentials / port / internal addresses.
refused("http (not https)", "http://www.googleapis.com/upload/drive/v3/files");
refused("file://", "file:///etc/passwd");
refused("loopback literal", "https://127.0.0.1/upload/drive/v3/files");
refused("cloud metadata", "http://169.254.169.254/");
refused("cloud metadata over https", "https://169.254.169.254/upload/drive/v3/files");
refused("non-443 port on an allowed host", "https://www.googleapis.com:8080/upload/drive/v3/files");
refused("embedded credentials", "https://user:pass@www.googleapis.com/upload/drive/v3/files");
refused("foreign path on an allowed host", "https://www.googleapis.com/some/other/path");
refused("path prefix collision (…/filesXXX)", "https://www.googleapis.com/upload/drive/v3/filesXXX/steal");
refused("not a URL at all", "not a url");
refused("empty string", "");

// The genuine article, in the shapes Google actually hands out.
for (const [label, url] of [
  ["resumable session URI with query", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=abc"],
  ["session URI on a file id", "https://www.googleapis.com/upload/drive/v3/files/STAGED1?uploadType=resumable&upload_id=abc"],
  ["apex host", "https://googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=abc"],
  ["explicit :443", "https://www.googleapis.com:443/upload/drive/v3/files?upload_id=abc"],
  ["trailing dot in host", "https://www.googleapis.com./upload/drive/v3/files?upload_id=abc"],
  ["upload subdomain", "https://upload.googleapis.com/upload/drive/v3/files?upload_id=abc"],
]) {
  let ok = false;
  let msg = "";
  try {
    const u = assertGoogleUploadUrl(url);
    ok = u instanceof URL;
  } catch (e) {
    msg = e instanceof Error ? e.message : String(e);
  }
  check(`accepted: ${label}`, ok, msg);
}

// ── 2. through the real tool: refusals make ZERO outbound requests ───────────

let fetchCount = 0;
let lastInit = null;
let responder = () => {
  throw new Error("responder not set");
};
globalThis.fetch = async (url, init = {}) => {
  fetchCount++;
  lastInit = init;
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

const fakeClients = {
  names: ["personal"],
  defaultName: "personal",
  multi: false,
  canonicalName: (n) => (n && n.trim() ? n.trim() : "personal"),
  emailFor: () => "me@personal.test",
  resolve: () => ({
    gmail: { users: { messages: { get: async () => ({ data: { payload: {} } }) } } },
    drive: { files: {} },
    docs: {},
    accessToken: async () => "ya29.FAKE",
  }),
  baseGmailQuery: () => "",
};

const server = new McpServer({ name: "confirm-upload-ssrf", version: "0" });
registerGmailTools(server, fakeClients, { store: null, userToken: null, consentStore: null, consentCfg: null });
const client = new Client({ name: "c", version: "0" });
const [a, b] = InMemoryTransport.createLinkedPair();
await Promise.all([server.connect(b), client.connect(a)]);

const confirm = async (uploads) => {
  const r = await client.callTool({ name: "gmail_confirm_upload", arguments: { uploads } });
  return { text: r.content[0].text, json: JSON.parse(r.content[0].text) };
};

console.log("\n[2] the tool refuses hostile addresses WITHOUT opening a socket");
for (const [label, url] of [
  ["path decoy (evil.example.com/googleapis.com/upload)", "https://evil.example.com/googleapis.com/upload"],
  ["suffix decoy (googleapis.com.evil.com)", "https://googleapis.com.evil.com/upload/drive/v3/files"],
  ["prefix decoy (evil-googleapis.com)", "https://evil-googleapis.com/upload/drive/v3/files"],
  ["plain http", "http://www.googleapis.com/upload/drive/v3/files"],
  ["loopback", "https://127.0.0.1/upload/drive/v3/files"],
  ["cloud metadata", "http://169.254.169.254/"],
  ["odd port", "https://www.googleapis.com:8080/upload/drive/v3/files"],
  ["embedded credentials", "https://user:pass@www.googleapis.com/upload/drive/v3/files"],
  ["foreign path on the allowed host", "https://www.googleapis.com/some/other/path"],
]) {
  fetchCount = 0;
  responder = () => res({ status: 200, body: "SHOULD NEVER BE REACHED" });
  const { json } = await confirm([{ uploadUrl: url }]);
  check(`${label} → refused`, /^🛑/.test(json.results[0].error ?? ""), JSON.stringify(json.results[0]));
  check(`${label} → ZERO outbound requests`, fetchCount === 0, String(fetchCount));
}

console.log("\n[3] a legitimate session URI is allowed through and still answers");
{
  fetchCount = 0;
  responder = () => res({ status: 308, headers: { range: "bytes=0-999" } });
  const { json } = await confirm([
    { uploadUrl: "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=abc", sizeBytes: 5000 },
  ]);
  check("exactly one outbound request", fetchCount === 1, String(fetchCount));
  check("308 without Location still reads as in_progress", json.results[0].status === "in_progress", JSON.stringify(json.results[0]));
  check("request was sent with redirect: manual", lastInit?.redirect === "manual", String(lastInit?.redirect));
  check("request carries an abort signal (timeout wired)", !!lastInit?.signal, String(lastInit?.signal));
}

console.log("\n[4] a redirect is refused, never followed");
{
  fetchCount = 0;
  responder = () => res({ status: 302, headers: { location: "https://169.254.169.254/latest/meta-data/" } });
  const { json } = await confirm([
    { uploadUrl: "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=abc" },
  ]);
  check("only the first request happened", fetchCount === 1, String(fetchCount));
  check("redirect reported as a refusal", /^🛑/.test(json.results[0].error ?? "") && /перенаправ/i.test(json.results[0].error ?? ""), JSON.stringify(json.results[0]));
}

console.log("\n[5] the body of an unexpected answer NEVER reaches the tool result");
{
  fetchCount = 0;
  let bodyRead = false;
  responder = () => ({
    ok: false,
    status: 500,
    headers: { get: () => null },
    text: async () => {
      bodyRead = true;
      return "SUPER-SECRET-INTERNAL-BODY";
    },
  });
  const { text, json } = await confirm([
    { uploadUrl: "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=abc" },
  ]);
  check("secret body absent from the whole tool result", !text.includes("SUPER-SECRET-INTERNAL-BODY"), text.slice(0, 200));
  check("status 500 is still reported", /500/.test(json.results[0].error ?? ""), JSON.stringify(json.results[0]));
  check("the body was not even read", bodyRead === false, String(bodyRead));
}

console.log("\n[6] a batch refuses the hostile item and still probes the good one");
{
  fetchCount = 0;
  responder = () => res({ status: 200, body: JSON.stringify({ id: "STAGED1", name: "f.bin", size: "10" }) });
  const { json } = await confirm([
    { uploadUrl: "https://evil.example.com/googleapis.com/upload" },
    { uploadUrl: "https://www.googleapis.com/upload/drive/v3/files/STAGED1?uploadType=resumable&upload_id=abc" },
  ]);
  check("one outbound request only (the good one)", fetchCount === 1, String(fetchCount));
  check("hostile item refused", /^🛑/.test(json.results[0].error ?? ""), JSON.stringify(json.results[0]));
  check("good item completed", json.results[1].status === "complete", JSON.stringify(json.results[1]));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
