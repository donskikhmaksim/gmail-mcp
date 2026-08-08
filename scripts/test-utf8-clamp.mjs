#!/usr/bin/env node
/**
 * Обрезка текста НИКОГДА не разрывает эмодзи пополам — ни в журнале согласий,
 * ни в превью плана, которое человек читает перед нажатием ✅.
 *
 * Приёмка 2026-08-07 (Н-6): `safeText` обрезала строку через `slice`, то есть
 * по UTF-16-единицам. Всё, что вне BMP (эмодзи, 𝕏), занимает ДВЕ такие
 * единицы, и если граница обрезки попадала между ними, наружу уезжал непарный
 * суррогат. В ответе `gmail_consent_audit` на 100 записях таких половинок
 * нашлось 10: `json.loads()` их ещё принимает, а `.encode('utf-8')` уже
 * падает — то есть любой клиент, пишущий ответ в файл/сокет/БД, спотыкается.
 *
 * Отдельно и намеренно проверяется МУТИРУЮЩАЯ ветка: та же функция строит
 * превью плана gmail_send. Обрыв там означает, что человек подтверждает
 * отправку по битому тексту, а не только что журнал плохо кодируется.
 *
 * Ключевое свойство фикстур: эмодзи стоит РОВНО НА ГРАНИЦЕ лимита. Тест с
 * эмодзи в середине строки прошёл бы и на сломанном коде — по ложной причине.
 *
 * Usage: node scripts/test-utf8-clamp.mjs
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { safeText, safeBlock } from "../dist/util.js";
import { registerGmailTools } from "../dist/tools/gmail.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${JSON.stringify(extra)}`}`);
  if (!cond) failures++;
};

/** Непарный суррогат: половина пары, оставшаяся без своей второй половины. */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const hasLoneSurrogate = (s) => LONE_SURROGATE.test(s);
/** Именно тот шаг, на котором падал клиент: строка → байты UTF-8 → строка. */
const utf8RoundTrips = (s) => Buffer.from(s, "utf8").toString("utf8") === s;

const ROCKET = "🚀"; // U+1F680 — вне BMP, две UTF-16-единицы

/**
 * Строка, у которой эмодзи начинается РОВНО на последней позиции, куда
 * дотягивается обрезка: `max - 1` символов бюджета, из них первые `max - 2` —
 * ASCII. Старый `slice(0, max - 1)` резал ровно между половинками пары.
 */
const onBoundary = (max) => "a".repeat(max - 2) + ROCKET + "хвост".repeat(20);

// --- 1. safeText: эмодзи на границе ----------------------------------------

console.log("\n[1] safeText — эмодзи ровно на границе лимита");
for (const max of [120, 60, 100, 200, 21]) {
  const out = safeText(onBoundary(max), max);
  check(`max=${max}: нет непарных суррогатов`, !hasLoneSurrogate(out), out.slice(-6));
  check(`max=${max}: кодируется в UTF-8 без потерь`, utf8RoundTrips(out), out.slice(-6));
  check(`max=${max}: обещание «не длиннее max» соблюдено`, out.length <= max, out.length);
  check(`max=${max}: обрезка действительно случилась`, out.endsWith("…"), out.slice(-3));
}

// --- 2. подряд идущие эмодзи (граница попадает в любую из пар) -------------

console.log("\n[2] строка целиком из эмодзи — режется по кодовым точкам");
for (const max of [40, 41, 42, 43]) {
  const out = safeText(ROCKET.repeat(80), max);
  check(`max=${max}: нет непарных суррогатов`, !hasLoneSurrogate(out), out.slice(-4));
  check(`max=${max}: длина в пределах лимита`, out.length <= max, out.length);
}

// --- 3. safeBlock (превью тела письма) поверх той же функции ---------------

console.log("\n[3] safeBlock — многострочное превью тела");
const blockOut = safeBlock([onBoundary(200), onBoundary(200)].join("\n"), { maxLines: 5, maxChars: 700, lineMax: 200 });
check("нет непарных суррогатов", !hasLoneSurrogate(blockOut), blockOut.slice(-8));
check("кодируется в UTF-8", utf8RoundTrips(blockOut), blockOut.slice(-8));

// --- 4. обычный текст не пострадал ----------------------------------------

console.log("\n[4] короткие строки и обычный текст — без изменений");
check("эмодзи внутри короткой строки сохраняется целиком", safeText(`Привет ${ROCKET} мир`, 120) === `Привет ${ROCKET} мир`, safeText(`Привет ${ROCKET} мир`, 120));
check("ASCII-обрезка по-прежнему ровно max", safeText("a".repeat(500), 120).length === 120, safeText("a".repeat(500), 120).length);

// --- 5. МУТИРУЮЩАЯ ВЕТКА: превью плана, которое читает человек -------------

console.log("\n[5] превью плана gmail_send — текст под кнопкой ✅");

const clock = { t: 1_700_000_000_000 };
const consentCfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now: () => clock.t };
function makeConsentStore() {
  const manifests = new Map();
  return {
    async createManifest(input) { manifests.set(input.id, { ...input, status: "AWAITING_CONSENT" }); },
    async getManifest(id, server) { const r = manifests.get(id); return r && r.server === server ? { ...r } : null; },
    async consumeManifest() { return null; },
    async invalidateManifest() {},
    async appendConsentAudit() {},
    async updateConsentAuditOutcome() {},
  };
}
const fakeClients = {
  names: ["personal"],
  defaultName: "personal",
  multi: false,
  canonicalName: (n) => (n && n.trim() ? n.trim() : "personal"),
  emailFor: () => "me@personal.test",
  resolve: () => ({ gmail: { users: { getProfile: async () => ({ data: { emailAddress: "me@personal.test" } }) } }, drive: {}, docs: {}, accessToken: async () => "ya29.FAKE" }),
  baseGmailQuery: () => "",
};
const server = new McpServer({ name: "gmail-mcp-test", version: "0" });
registerGmailTools(server, fakeClients, {
  store: null,
  userToken: null,
  consentStore: makeConsentStore(),
  consentCfg,
});
const client = new Client({ name: "test-client", version: "0" });
const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
await Promise.all([server.connect(serverSide), client.connect(clientSide)]);

// Тема обрезается на 200 (`safeText(it.subject, 200)`), строки тела — тоже на
// 200 (`safeBlock(..., lineMax: 200)`); эмодзи ставим ровно на эти границы.
const planResp = await client.callTool({
  name: "gmail_send",
  arguments: {
    account: "personal",
    messages: [{ to: "friend@example.com", subject: onBoundary(200), body: [onBoundary(200), "вторая строка", onBoundary(200)].join("\n") }],
  },
});
const previewText = planResp.content[0].text;
check("план построен (ничего не отправлено)", previewText.includes("план"), previewText.slice(0, 80));
check("в превью НЕТ непарных суррогатов", !hasLoneSurrogate(previewText), previewText.slice(-40));
check("превью кодируется в UTF-8 без потерь", utf8RoundTrips(previewText), previewText.slice(-40));
check("превью действительно обрезано (в нём есть …)", previewText.includes("…"), previewText.slice(-40));
check(
  "весь ответ целиком (включая _meta) кодируется в UTF-8",
  utf8RoundTrips(JSON.stringify(planResp)),
  "",
);

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
