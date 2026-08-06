#!/usr/bin/env node
/**
 * Safety headers on `/dl/:token` (src/http.ts) — the unauthenticated route
 * that serves one attachment's bytes to whoever holds the link.
 *
 * `Content-Disposition: attachment` (already there) stops the browser from
 * RENDERING an HTML attachment when the link is opened directly. What it does
 * not cover: a third-party page can pull the same URL in as a SUBRESOURCE
 * (`<script src=…>`, `<object>`, `<embed>`), where a browser is free to sniff
 * the bytes and execute them as whatever type it guessed — on this server's
 * own origin. `X-Content-Type-Options: nosniff` closes that. It is a second
 * line of defence (the attacker needs the secret link first), which is exactly
 * why it needs a regression test: nobody would notice it going missing.
 *
 * Both headers are asserted, so neither can be quietly dropped later.
 *
 * The route sets them as soon as the token resolves — BEFORE the Gmail call —
 * so they hold on every exit path. That is also what makes this test offline:
 * with no Google account linked the route answers 503 without touching the
 * network, and the headers must already be on that answer.
 *
 * Usage: node scripts/test-dl-headers.mjs
 */
import { startHttpServer } from "../dist/http.js";
import { initDownloads, issueDownloadLink } from "../dist/downloads.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${JSON.stringify(extra)}`}`);
  if (!cond) failures++;
};

const PORT = 34911;
const BASE = `http://127.0.0.1:${PORT}`;

// No users and no onboarding => the route reaches its "no account linked"
// answer without any outbound call. Nothing here talks to Google.
await startHttpServer({
  transport: "http",
  port: PORT,
  requireAuth: false,
  users: [],
  onboarding: { enabled: false },
  sendingStuckMinutes: 10,
});

initDownloads(BASE);
const { url } = await issueDownloadLink(
  {
    account: "personal",
    messageId: "MSG1",
    attachmentId: "ATT1",
    // A name that would be dangerous if the browser were allowed to sniff it.
    name: "payload.html",
    mimeType: "text/html",
    size: 42,
  },
  30,
);
const token = url.split("/dl/")[1];

console.log("\n[1] a resolved token always carries the safety headers");
{
  const res = await fetch(`${BASE}/dl/${token}`);
  const sniff = res.headers.get("x-content-type-options");
  const disp = res.headers.get("content-disposition") ?? "";
  check("X-Content-Type-Options: nosniff", sniff === "nosniff", sniff);
  check("Content-Disposition forces a download (attachment; …)", disp.startsWith("attachment"), disp);
  check("Content-Disposition carries the file name", /payload\.html/.test(disp), disp);
  check("Cache-Control keeps shared caches out", (res.headers.get("cache-control") ?? "").includes("no-store"), res.headers.get("cache-control"));
  check("no Google account linked here, so the route stops at 503 (offline)", res.status === 503, res.status);
}

console.log("\n[2] an unknown token gets a neutral 404, nothing else");
{
  const res = await fetch(`${BASE}/dl/definitely-not-a-real-token`);
  const body = await res.text();
  check("404", res.status === 404, res.status);
  check("body says nothing about why", /invalid or has expired/.test(body) && !/account|gmail|token=/i.test(body), body.slice(0, 120));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
