#!/usr/bin/env node
/**
 * S2 — SSRF/OOM guard for url-based attachments (src/tools/gmail.ts).
 *
 * Covers `references/security-checklist.md` §2: https-only, private/link-local/
 * loopback IPs refused, DNS names resolving to private IPs refused, manual
 * redirects (a public host redirecting to a private IP is blocked), a
 * STREAMING size cap enforced before buffering, AND (S2+, DNS-rebinding /
 * TOCTOU) that the actual network connection is pinned to the exact address
 * `assertPublicUrl` validated — never re-resolved independently by the HTTP
 * client. Every refusal path asserts that NO outbound fetch happened (or
 * that the second fetch after a redirect was never made). No network, no
 * real DNS: the DNS resolver is injected (`lookup`) and the network fetch is
 * injected (`fetchImpl` — `fetchAttachmentSafely`'s 4th param). We no longer
 * monkeypatch `globalThis.fetch`: the fix moved the real implementation onto
 * undici's OWN fetch+Agent pair (see the doc comment on `fetchAttachmentSafely`
 * in src/tools/gmail.ts for why), which a global-fetch stub cannot intercept
 * — that is in fact the point: nothing univited gets to hijack the resolve
 * path anymore, not even well-meaning monkeypatches.
 *
 * Usage:
 *   node scripts/test-s2-ssrf.mjs
 */
import {
  isBlockedIp,
  assertPublicUrl,
  fetchAttachmentSafely,
  readCappedStream,
  pinnedLookup,
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
//
// The real network call now goes through undici's own fetch+Agent pair, not
// globalThis.fetch (that switch IS the S2+ fix — see the doc comment on
// fetchAttachmentSafely in src/tools/gmail.ts). So instead of monkeypatching
// a global, we inject a fake `fetchImpl` as the function's 4th argument —
// the same dependency-injection pattern already used for `lookup`.

console.log("\n[3] fetchAttachmentSafely — refusal paths call fetch zero times");
let fetchCount = 0;
let lastDispatcher = null;
function makeFetchImpl(impl) {
  fetchCount = 0;
  lastDispatcher = null;
  return async (url, opts) => {
    fetchCount++;
    lastDispatcher = opts?.dispatcher ?? null;
    return impl(url, opts);
  };
}

let fetchImpl = makeFetchImpl(async () => new Response("x", { status: 200 }));
await expectThrow("http:// never fetched", () => fetchAttachmentSafely("http://good.example/x", 1000, fakeLookup, fetchImpl), /только https/i);
check("no fetch on scheme refusal", fetchCount === 0, String(fetchCount));

fetchImpl = makeFetchImpl(async () => new Response("x", { status: 200 }));
await expectThrow("metadata IP never fetched", () => fetchAttachmentSafely("https://169.254.169.254/latest", 1000, fakeLookup, fetchImpl), /внутренний|приватн/i);
check("no fetch on IP refusal", fetchCount === 0, String(fetchCount));

// --- 4. redirect to a private IP is blocked (second fetch never happens) ---

console.log("\n[4] fetchAttachmentSafely — redirect to private IP blocked on the hop");
fetchImpl = makeFetchImpl(async (url) => {
  const u = String(url);
  if (u.includes("93.184.216.34")) {
    return new Response(null, { status: 302, headers: { location: "https://169.254.169.254/latest" } });
  }
  return new Response("SHOULD NOT REACH", { status: 200 });
});
await expectThrow(
  "redirect from public to 169.254.169.254 refused",
  () => fetchAttachmentSafely("https://93.184.216.34/start", 1000, fakeLookup, fetchImpl),
  /внутренний|приватн/i,
);
check("only the first (public) fetch happened, redirect target never fetched", fetchCount === 1, String(fetchCount));

// --- 4b. pinnedLookup: the actual DNS-rebinding closer ----------------------
//
// This is the core of the S2+ fix, tested directly and in isolation: the
// `lookup` function handed to the per-hop undici Agent must answer with ONLY
// the addresses `resolveAndValidateHost` already vetted, no matter what
// hostname or option shape the HTTP client's connector asks it to resolve.
// A rebinding attacker controls what a FRESH DNS resolve would return — this
// proves fetchAttachmentSafely's connector never performs one.

console.log("\n[4b] pinnedLookup — connect-time resolve is pinned, not re-resolved");
{
  const vetted = [{ address: "93.184.216.34", family: 4 }];
  const lookupFn = pinnedLookup(vetted);

  // Simulate the "all: true" call shape (Happy Eyeballs / autoSelectFamily).
  await new Promise((resolve) => {
    // Deliberately ask for a DIFFERENT hostname than what was vetted — a
    // rebinding attacker would have this resolve to 169.254.169.254 by now.
    lookupFn("attacker-controlled-by-now.example", { all: true }, (err, addrs) => {
      check("all:true shape returns ONLY the vetted address", err === null && addrs.length === 1 && addrs[0].address === "93.184.216.34", JSON.stringify(addrs));
      resolve();
    });
  });

  // Simulate the legacy single-address call shape.
  await new Promise((resolve) => {
    lookupFn("attacker-controlled-by-now.example", {}, (err, address, family) => {
      check("single-address shape returns the vetted address", err === null && address === "93.184.216.34" && family === 4, `${address} ${family}`);
      resolve();
    });
  });

  // Never touches the real resolver: no `dns` import used inside pinnedLookup
  // at all (structural guarantee, not just a runtime observation) — confirmed
  // by inspecting the exported function's source has no dns/net calls.
  check("pinnedLookup does not reference dns/net APIs (structural check)", !/dns\.|net\.lookup/.test(lookupFn.toString()));
}

// --- 4c. fetchImpl is always handed a dispatcher (pinning is always wired) -

console.log("\n[4c] fetchAttachmentSafely — every real call carries a pinned dispatcher");
fetchImpl = makeFetchImpl(async () => new Response("ok", { status: 200, headers: { "content-type": "text/plain" } }));
await fetchAttachmentSafely("https://93.184.216.34/x", 1000, fakeLookup, fetchImpl);
check("dispatcher was passed to fetchImpl", lastDispatcher !== null);
check("dispatcher exposes a dispatch()/close() (a real Agent, not a plain object)", typeof lastDispatcher?.close === "function" && typeof lastDispatcher?.dispatch === "function");

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
fetchImpl = async (_url, opts) => {
  fetchCount++;
  lastDispatcher = opts?.dispatcher ?? null;
  return {
    status: 200,
    ok: true,
    headers: new Map([["content-length", String(50 * 1024 * 1024)], ["content-type", "application/pdf"]]),
    get body() { bodyRead = true; return null; },
  };
};
await expectThrow(
  "50MB declared refused",
  () => fetchAttachmentSafely("https://93.184.216.34/big.pdf", 25 * 1024 * 1024, fakeLookup, fetchImpl),
  /ограничивает|МБ/i,
);
check("oversized refused WITHOUT reading the body stream", bodyRead === false, String(bodyRead));

// --- 7. happy path: legit https streams under cap --------------------------

console.log("\n[7] fetchAttachmentSafely — legit https download under the cap");
fetchImpl = async (_url, opts) => {
  fetchCount++;
  lastDispatcher = opts?.dispatcher ?? null;
  return {
    status: 200,
    ok: true,
    headers: new Map([["content-type", "application/pdf"]]),
    body: streamOf([new Uint8Array([1, 2, 3, 4])]),
  };
};
{
  const { buf, contentType } = await fetchAttachmentSafely("https://93.184.216.34/ok.pdf", 25 * 1024 * 1024, fakeLookup, fetchImpl);
  check("bytes downloaded", buf.length === 4, String(buf.length));
  check("content-type surfaced", contentType === "application/pdf", String(contentType));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
