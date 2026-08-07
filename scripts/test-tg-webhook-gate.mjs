#!/usr/bin/env node
/**
 * TG_WEBHOOK_OWNER route-level gate on `/tg/webhook` (src/http.ts).
 *
 * Context: `consumeTgDecisionAnyServer` (the prior fix on this branch, see
 * `git log` for `fix(tg-approval): server-agnostic webhook consume +
 * TG_WEBHOOK_OWNER guard`) made webhook *consume* server-agnostic across all
 * 6 MCP servers that will eventually share one Telegram bot token
 * (gmail/sheets/calendar/docs/drive-mcp + ticktick-mcp), because
 * `manifest_id` is `tg_approvals`' globally-unique PRIMARY KEY. That fix by
 * itself left a hole: `/tg/webhook` was mounted UNCONDITIONALLY on every
 * server, guarded only by `TG_APPROVAL_WEBHOOK_SECRET`. Leaking that secret
 * on ANY ONE of the 6 servers would let an attacker decide approvals for
 * every other server too -- including gmail_send on gmail-mcp, the most
 * dangerous one. This test proves the new gate: a server that isn't the
 * designated webhook owner (`TG_WEBHOOK_OWNER` unset/false) must refuse the
 * route entirely, even with the CORRECT secret, before the handler runs.
 *
 * Why this file spawns two CHILD PROCESSES instead of just calling
 * `startHttpServer` twice with different config objects (the pattern
 * `test-s5-failclosed.mjs` uses for MCP_AUTH_TOKEN scenarios): unlike
 * `requireAuth`, `TG_WEBHOOK_OWNER` is NOT threaded through the `Config`
 * object passed to `startHttpServer` -- the route handler closes over the
 * module-level singleton `tgApprovalConfig` (`src/server.ts`), computed
 * ONCE from `process.env` at import time. A single process can only ever
 * observe one value of it. So each scenario below gets its own `node`
 * process with its own env, self-invoking this same file with
 * `TG_TEST_WORKER` set (worker mode), and the parent (orchestrator mode,
 * no env var set) collects + checks the JSON result line each worker prints.
 *
 * Proving "the handler was never called" (not just "got a 404"), per the
 * plan's ask: the worker never calls `initStore()` (that only happens in
 * `src/index.ts`'s real startup, which this test bypasses like
 * `test-s5-failclosed.mjs` does), so `store.ts`'s internal pg Pool is never
 * constructed. If `handleWebhook` -> `consumeTgDecisionAnyServer` is ever
 * actually invoked, it throws "Store not initialised", caught by http.ts's
 * `try { await handleWebhook(...) } catch (err) { console.error("TG
 * approval webhook error:", err); }` -- a distinctive, capturable log line
 * that only exists if execution reached past the gate into the real
 * handler. Absence of that line (owner=false) is the "handler not called"
 * proof; presence of it exactly once (owner=true) is the "handler WAS
 * called, same as before this fix" regression proof.
 *
 * Usage: node scripts/test-tg-webhook-gate.mjs  (after `npm run build`)
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const THIS_FILE = fileURLToPath(import.meta.url);
const BOT_TOKEN = "TESTTOKEN";
// Deliberately a DIFFERENT string from BOT_TOKEN (not just a second alias for
// the same value) — proves `botToken = TG_BOT_TOKEN_OVERRIDE || TG_BOT_TOKEN`
// actually PICKS the override, rather than the test coincidentally passing
// because both env vars happened to hold the same token.
const OWN_BOT_TOKEN = "OWNBOTTOKEN";
const OWNER_CHAT_ID = "555";
const WEBHOOK_SECRET = "wh-secret-xyz";

// ── worker mode: run ONE scenario in this (child) process, print result JSON ──
async function runWorker() {
  const scenario = process.env.TG_TEST_WORKER; // "owner-false" | "owner-true"
  const port = Number(process.env.TG_TEST_PORT);

  const { MockAgent, setGlobalDispatcher } = await import("undici");
  const agent = new MockAgent();
  // Block any un-mocked network call from reaching the real internet (in
  // particular the real api.telegram.org), EXCEPT loopback -- the test's own
  // fetch() to the local server it just started also goes through this same
  // global dispatcher (Node's fetch uses undici under the hood), so 127.0.0.1
  // must stay allowed or the test can't talk to its own server at all.
  agent.disableNetConnect();
  agent.enableNetConnect(/^127\.0\.0\.1/);
  setGlobalDispatcher(agent);
  let setWebhookCalls = 0;
  let ownBotSetWebhookCalls = 0;
  const pool = agent.get("https://api.telegram.org");
  pool
    .intercept({ path: `/bot${BOT_TOKEN}/setWebhook`, method: "POST" })
    .reply(() => {
      setWebhookCalls++;
      return { statusCode: 200, data: { ok: true, result: true }, headers: { "content-type": "application/json" } };
    })
    .persist();
  // Separate interceptor, separate counter, DIFFERENT bot token path — lets
  // own-bot scenarios prove `registerWebhook` called `setWebhook` against
  // THIS bot specifically, not (accidentally-indistinguishably) the shared one.
  pool
    .intercept({ path: `/bot${OWN_BOT_TOKEN}/setWebhook`, method: "POST" })
    .reply(() => {
      ownBotSetWebhookCalls++;
      return { statusCode: 200, data: { ok: true, result: true }, headers: { "content-type": "application/json" } };
    })
    .persist();

  const loggedErrors = [];
  const origConsoleError = console.error;
  console.error = (...args) => {
    loggedErrors.push(args.map(String).join(" "));
  };

  const { startHttpServer } = await import(new URL("../dist/http.js", import.meta.url));

  const fakeAccount = {
    name: "default",
    auth: { mode: "oauth", clientId: "test-cid", clientSecret: "test-secret", refreshToken: "test-refresh" },
  };
  await startHttpServer({
    transport: "http",
    port,
    requireAuth: false,
    users: [{ name: "default", accounts: [fakeAccount], defaultAccount: "default" }],
    onboarding: { enabled: false },
    sendingStuckMinutes: 10,
  });

  // A callback_query that WOULD be processed if the gate let it through:
  // from.id matches TG_OWNER_CHAT_ID and data matches the "a:<manifestId>"
  // regex `handleWebhook` expects (src/tg_approval.ts) -- so if the gate is
  // bypassed, execution reaches consumeTgDecisionAnyServer.
  const res = await fetch(`http://127.0.0.1:${port}/tg/webhook`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-telegram-bot-api-secret-token": WEBHOOK_SECRET,
    },
    body: JSON.stringify({
      callback_query: {
        id: "cbq-gate-test",
        from: { id: Number(OWNER_CHAT_ID) },
        data: "a:fake-manifest-id-gate-test",
        message: { message_id: 1, chat: { id: Number(OWNER_CHAT_ID) } },
      },
    }),
  });

  console.error = origConsoleError;

  const handlerErrorLines = loggedErrors.filter((l) => l.includes("TG approval webhook error:"));
  const reachedStoreNotInitialised = handlerErrorLines.some((l) => l.includes("Store not initialised"));
  // TG_BOT_TOKEN_OVERRIDE (own-bot) hazard warning — registerWebhook logs this
  // loudly when BOTH TG_WEBHOOK_OWNER=true and the override are set on the
  // same process (see tg_approval.ts's registerWebhook doc comment).
  const sawBothFlagsWarning = loggedErrors.some((l) => l.includes("TG_WEBHOOK_OWNER=true И"));

  process.stdout.write(
    JSON.stringify({
      scenario,
      status: res.status,
      handlerErrorLineCount: handlerErrorLines.length,
      reachedStoreNotInitialised,
      setWebhookCalls,
      ownBotSetWebhookCalls,
      sawBothFlagsWarning,
    }) + "\n",
  );
  process.exit(0);
}

// ── orchestrator mode: spawn both scenarios as children, check their results ──
function runOrchestrator() {
  let failures = 0;
  const check = (label, cond, extra = "") => {
    console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
    if (!cond) failures++;
  };

  function spawnScenario(scenario, port, webhookOwnerEnv, botTokenOverrideEnv = null) {
    const result = spawnSync(process.execPath, [THIS_FILE], {
      encoding: "utf8",
      env: {
        ...process.env,
        TG_TEST_WORKER: scenario,
        TG_TEST_PORT: String(port),
        TG_APPROVAL_ENABLED: "true",
        TG_BOT_TOKEN: BOT_TOKEN,
        TG_OWNER_CHAT_ID: OWNER_CHAT_ID,
        TG_APPROVAL_WEBHOOK_SECRET: WEBHOOK_SECRET,
        PUBLIC_BASE_URL: "https://example.test",
        ...(webhookOwnerEnv === null ? {} : { TG_WEBHOOK_OWNER: webhookOwnerEnv }),
        ...(botTokenOverrideEnv === null ? {} : { TG_BOT_TOKEN_OVERRIDE: botTokenOverrideEnv }),
        DATABASE_URL: "",
      },
      timeout: 15_000,
    });
    if (result.status !== 0) {
      console.error(`worker[${scenario}] exited ${result.status}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
      return null;
    }
    const lastLine = result.stdout.trim().split("\n").filter(Boolean).pop();
    try {
      return JSON.parse(lastLine);
    } catch {
      console.error(`worker[${scenario}] did not print JSON. stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
      return null;
    }
  }

  // ═══ [a] TG_WEBHOOK_OWNER unset (default false) + CORRECT secret → 404, handler never runs ═══
  console.log("\n[a] webhookOwner НЕ задан (default false) + верный секрет → 404, handler не вызывается");
  {
    const r = spawnScenario("owner-false-default", 34960, null);
    check("worker завершился и вернул результат", !!r, "worker crashed or printed no JSON");
    if (r) {
      check("статус 404", r.status === 404, r.status);
      check(
        "handleWebhook НЕ вызывался (нет ни одной строки 'TG approval webhook error:')",
        r.handlerErrorLineCount === 0,
        r.handlerErrorLineCount,
      );
      check("setWebhook при старте не вызывался (registerWebhook тоже не-owner)", r.setWebhookCalls === 0, r.setWebhookCalls);
    }
  }

  // ═══ [b] TG_WEBHOOK_OWNER=false explicitly + CORRECT secret → 404, handler never runs ═══
  console.log("\n[b] webhookOwner=false ЯВНО + верный секрет → 404, handler не вызывается");
  {
    const r = spawnScenario("owner-false-explicit", 34961, "false");
    check("worker завершился и вернул результат", !!r, "worker crashed or printed no JSON");
    if (r) {
      check("статус 404", r.status === 404, r.status);
      check(
        "handleWebhook НЕ вызывался (нет ни одной строки 'TG approval webhook error:')",
        r.handlerErrorLineCount === 0,
        r.handlerErrorLineCount,
      );
    }
  }

  // ═══ [c] control: TG_WEBHOOK_OWNER=true + CORRECT secret → 200, handler DOES run (regression check) ═══
  console.log("\n[c] контроль: webhookOwner=true + верный секрет → 200, handler ВЫЗЫВАЕТСЯ (как раньше, без регресса)");
  {
    const r = spawnScenario("owner-true", 34962, "true");
    check("worker завершился и вернул результат", !!r, "worker crashed or printed no JSON");
    if (r) {
      check("статус 200 (регресс на старое поведение не сломан)", r.status === 200, r.status);
      check(
        "handleWebhook РЕАЛЬНО вызывался ровно один раз (ровно одна строка 'TG approval webhook error:')",
        r.handlerErrorLineCount === 1,
        r.handlerErrorLineCount,
      );
      check(
        "вызов дошёл до consumeTgDecisionAnyServer (упал на 'Store not initialised', а не раньше)",
        r.reachedStoreNotInitialised === true,
        r,
      );
      check("registerWebhook по-прежнему вызывает setWebhook ровно один раз при старте (happy path не сломан)", r.setWebhookCalls === 1, r.setWebhookCalls);
    }
  }

  // ═══ [d] own-bot (TG_BOT_TOKEN_OVERRIDE) + TG_WEBHOOK_OWNER unset → 200, handler DOES run ═══
  // A server with its own bot owns its own webhook unconditionally — no
  // dependency on the shared-bot TG_WEBHOOK_OWNER flag at all. Same "reached
  // Store not initialised" proof as scenario [c], now via cfg.ownBot instead
  // of cfg.webhookOwner.
  console.log("\n[d] own-bot (TG_BOT_TOKEN_OVERRIDE) без TG_WEBHOOK_OWNER → 200, handler ВЫЗЫВАЕТСЯ");
  {
    const r = spawnScenario("own-bot-only", 34963, null, OWN_BOT_TOKEN);
    check("worker завершился и вернул результат", !!r, "worker crashed or printed no JSON");
    if (r) {
      check("статус 200 (own-bot принимает вебхук без TG_WEBHOOK_OWNER)", r.status === 200, r.status);
      check(
        "handleWebhook РЕАЛЬНО вызывался ровно один раз",
        r.handlerErrorLineCount === 1,
        r.handlerErrorLineCount,
      );
      check(
        "вызов дошёл до store.consumeTgDecision (упал на 'Store not initialised', а не раньше)",
        r.reachedStoreNotInitialised === true,
        r,
      );
      check(
        "registerWebhook вызывает setWebhook на СВОЙ бот-токен (override), НЕ на общий",
        r.ownBotSetWebhookCalls === 1 && r.setWebhookCalls === 0,
        r,
      );
      check("никакого предупреждения о конфликте флагов (только ownBot, не webhookOwner тоже)", r.sawBothFlagsWarning === false, r);
    }
  }

  // ═══ [e] both flags true (legacy webhookOwner=true + own-bot override) → still 200, but LOUD warning ═══
  // The explicit hazard called out in the task: gmail-mcp keeps its legacy
  // TG_WEBHOOK_OWNER=true (shared-bot webhook owner for the other 5 servers)
  // while ALSO getting its own TG_BOT_TOKEN_OVERRIDE one day. The route gate
  // must not 404 (both flags individually satisfy it — no double-mounting,
  // it's the same single Express handler either way), but registerWebhook
  // must log a loud warning that it just silently switched THIS process's
  // Telegram identity to the override, dropping the shared bot's webhook.
  console.log("\n[e] контроль конфликта: TG_WEBHOOK_OWNER=true И TG_BOT_TOKEN_OVERRIDE заданы одновременно → 200 + громкое предупреждение");
  {
    const r = spawnScenario("own-bot-plus-webhook-owner", 34964, "true", OWN_BOT_TOKEN);
    check("worker завершился и вернул результат", !!r, "worker crashed or printed no JSON");
    if (r) {
      check("статус 200 (маршрут не 404 — хотя бы один из флагов истинен)", r.status === 200, r.status);
      check("handleWebhook по-прежнему вызывается", r.handlerErrorLineCount === 1, r.handlerErrorLineCount);
      check(
        "setWebhook вызван на СВОЙ бот-токен (override победил) — общий бот НЕ регистрируется этим процессом",
        r.ownBotSetWebhookCalls === 1 && r.setWebhookCalls === 0,
        r,
      );
      check("предупреждение о конфликте флагов ЗАЛОГИРОВАНО", r.sawBothFlagsWarning === true, r);
    }
  }

  console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
  process.exit(failures ? 1 : 0);
}

if (process.env.TG_TEST_WORKER) {
  await runWorker();
} else {
  runOrchestrator();
}
