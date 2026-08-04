#!/usr/bin/env node
/**
 * S2 — SSRF/OOM guard for url-based attachments (src/tools/gmail.ts).
 *
 * Covers `references/security-checklist.md` §2: https-only, private/link-local/
 * loopback IPs refused, DNS names resolving to private IPs refused, manual
 * redirects (a public host redirecting to a private IP is blocked), and a
 * STREAMING size cap enforced before buffering. Every refusal path asserts that
 * NO outbound fetch happened (or that the second fetch after a redirect was
 * never made). No network, no real DNS: the DNS resolver and global.fetch are
 * both injected/stubbed.
 *
 * Usage:
 *   node scripts/test-s2-ssrf.mjs
 */
import {
  isBlockedIp,
  assertPublicUrl,
  fetchAttachmentSafely,
  readCappedStream,
} from "../dist/tools/gmail.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};
async function expectThrow(label, fn, re) {
  try {
    await fn();
    check(label, false, "did not throw");
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    check(label, re ? re.test(msg) : true, msg);
  }
}

// --- 1. isBlockedIp: the range table ---------------------------------------

console.log("\n[1] isBlockedIp — private/link-local/loopback blocked, public allowed");
for (const ip of [
  "127.0.0.1", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.1",
  "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1", "224.0.0.1",
  "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "::ffff:169.254.169.254",
  "::ffff:127.0.0.1", "not-an-ip",
]) {
  check(`blocked: ${ip}`, isBlockedIp(ip) === true, String(isBlockedIp(ip)));
}
for (const ip of ["8.8.8.8", "93.184.216.34", "1.1.1.1", "172.15.0.1", "172.32.0.1", "2606:4700::1111"]) {
  check(`allowed: ${ip}`, isBlockedIp(ip) === false, String(isBlockedIp(ip)));
}

// --- 2. assertPublicUrl: scheme + IP-literal + DNS -------------------------

console.log("\n[2] assertPublicUrl — refusals never touch DNS/fetch unnecessarily");
let dnsCalls = 0;
const fakeLookup = (host) => {
  dnsCalls++;
  // Map a couple of test hosts to controlled addresses.
  if (host === "evil.internal") return Promise.resolve([{ address: "169.254.169.254" }]);
  if (host === "good.example") return Promise.resolve([{ address: "93.184.216.34" }]);
  if (host === "mixed.example") return Promise.resolve([{ address: "93.184.216.34" }, { address: "10.0.0.5" }]);
  return Promise.resolve([]);
};

await expectThrow("http:// refused (scheme)", () => assertPublicUrl("http://good.example/x", fakeLookup), /только https/i);
check("scheme refusal did NOT hit DNS", dnsCalls === 0, String(dnsCalls));

await expectThrow("file:// refused", () => assertPublicUrl("file:///etc/passwd", fakeLookup), /только https/i);

await expectThrow("IP-literal 169.254.169.254 refused (no DNS)", () => assertPublicUrl("https://169.254.169.254/latest", fakeLookup), /внутренний|приватн/i);
check("IP-literal refusal did NOT hit DNS", dnsCalls === 0, String(dnsCalls));

await expectThrow("host resolving to link-local refused", () => assertPublicUrl("https://evil.internal/x", fakeLookup), /внутренний|приватн/i);
await expectThrow("host resolving to a mix incl. private refused", () => assertPublicUrl("https://mixed.example/x", fakeLookup), /внутренний|приватн/i);
await expectThrow("host resolving to nothing refused", () => assertPublicUrl("https://nowhere.example/x", fakeLookup), /не разрешается/i);

{
  const u = await assertPublicUrl("https://good.example/file.pdf", fakeLookup);
  check("legit https URL passes", u.hostname === "good.example");
}

// --- 3. fetchAttachmentSafely: refusals make ZERO outbound fetch -----------

console.log("\n[3] fetchAttachmentSafely — refusal paths call fetch zero times");
const realFetch = globalThis.fetch;
let fetchCount = 0;
function stubFetch(impl) {
  fetchCount = 0;
  globalThis.fetch = async (...args) => {
    fetchCount++;
    return impl(...args);
  };
}

stubFetch(async () => new Response("x", { status: 200 }));
await expectThrow("http:// never fetched", () => fetchAttachmentSafely("http://good.example/x", 1000, fakeLookup), /только https/i);
check("no fetch on scheme refusal", fetchCount === 0, String(fetchCount));

stubFetch(async () => new Response("x", { status: 200 }));
await expectThrow("metadata IP never fetched", () => fetchAttachmentSafely("https://169.254.169.254/latest", 1000, fakeLookup), /внутренний|приватн/i);
check("no fetch on IP refusal", fetchCount === 0, String(fetchCount));

// --- 4. redirect to a private IP is blocked (second fetch never happens) ---

console.log("\n[4] fetchAttachmentSafely — redirect to private IP blocked on the hop");
stubFetch(async (url) => {
  const u = String(url);
  if (u.includes("93.184.216.34")) {
    return new Response(null, { status: 302, headers: { location: "https://169.254.169.254/latest" } });
  }
  return new Response("SHOULD NOT REACH", { status: 200 });
});
await expectThrow(
  "redirect from public to 169.254.169.254 refused",
  () => fetchAttachmentSafely("https://93.184.216.34/start", 1000, fakeLookup),
  /внутренний|приватн/i,
);
check("only the first (public) fetch happened, redirect target never fetched", fetchCount === 1, String(fetchCount));

// --- 5. streaming size cap enforced before full buffering ------------------

console.log("\n[5] readCappedStream — aborts once the cap is exceeded");
function streamOf(chunks) {
  let i = 0;
  let canceled = false;
  return {
    getReader() {
      return {
        read: async () => (i < chunks.length ? { done: false, value: chunks[i++] } : { done: true, value: undefined }),
        cancel: async () => { canceled = true; },
        releaseLock: () => {},
        get canceled() { return canceled; },
      };
    },
  };
}
await expectThrow(
  "cap exceeded mid-stream throws",
  () => readCappedStream(streamOf([new Uint8Array(600), new Uint8Array(600)]), 1000),
  /лимит|прервано/i,
);
{
  const buf = await readCappedStream(streamOf([new Uint8Array(300), new Uint8Array(300)]), 1000);
  check("under-cap stream returns full buffer", buf.length === 600, String(buf.length));
}

// --- 6. oversized declared Content-Length refused up front -----------------

console.log("\n[6] fetchAttachmentSafely — oversized Content-Length refused before reading body");
let bodyRead = false;
// Response with a huge content-length header; body read must not even start.
// Our code uses resp.headers.get(...) — a Map has .get, good enough here.
globalThis.fetch = async () => {
  fetchCount++;
  return {
    status: 200,
    ok: true,
    headers: new Map([["content-length", String(50 * 1024 * 1024)], ["content-type", "application/pdf"]]),
    get body() { bodyRead = true; return null; },
  };
};
await expectThrow(
  "50MB declared refused",
  () => fetchAttachmentSafely("https://93.184.216.34/big.pdf", 25 * 1024 * 1024, fakeLookup),
  /ограничивает|МБ/i,
);
check("oversized refused WITHOUT reading the body stream", bodyRead === false, String(bodyRead));

// --- 7. happy path: legit https streams under cap --------------------------

console.log("\n[7] fetchAttachmentSafely — legit https download under the cap");
globalThis.fetch = async () => {
  fetchCount++;
  return {
    status: 200,
    ok: true,
    headers: new Map([["content-type", "application/pdf"]]),
    body: streamOf([new Uint8Array([1, 2, 3, 4])]),
  };
};
{
  const { buf, contentType } = await fetchAttachmentSafely("https://93.184.216.34/ok.pdf", 25 * 1024 * 1024, fakeLookup);
  check("bytes downloaded", buf.length === 4, String(buf.length));
  check("content-type surfaced", contentType === "application/pdf", String(contentType));
}

globalThis.fetch = realFetch;

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
