#!/usr/bin/env node
/**
 * Тест защиты исходящих запросов от SSRF (подделки запроса со стороны
 * сервера) — `src/safeFetch.ts`.
 *
 * Проверяются ВСЕ три рубежа, каждый — своим способом:
 *  [1][2] разбор адреса и классификация IP — чистая логика, без сети;
 *  [3] адрес, по которому РЕАЛЬНО идёт соединение: имя из allowlist,
 *      резолвящееся в приватный адрес (подмена разрешения имени, DNS
 *      rebinding), не доходит до сокета — локальный HTTP-сервер считает
 *      входящие запросы и не получает НИ ОДНОГО; плюс структурная проверка,
 *      что `pinnedLookup` не способен на повторный резолв;
 *  [4] перенаправления: адрес из `Location` проходит те же проверки, и
 *      редирект с разрешённого адреса на запрещённый обрывается ДО второго
 *      запроса.
 *
 * Сети наружу тест не требует: DNS-резолвер и транспорт инжектируются.
 *
 * Запуск: node scripts/test-ssrf-guard.mjs
 */
import http from "node:http";
import {
  assertAllowedGoogleUrl,
  isBlockedIp,
  safeGoogleFetch,
  pinnedLookup,
  BlockedUrlError,
} from "../dist/safeFetch.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};

/** Возвращает текст ошибки, если вызов бросил, иначе null. */
const throws = (fn) => {
  try {
    fn();
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
};

// ── 1. разбор адреса ────────────────────────────────────────────────────────

console.log("\n[1] assertAllowedGoogleUrl — что принимаем и что нет");

const ALLOWED = [
  "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=X",
  "https://storage.googleapis.com/upload/x",
  "https://lh3.googleusercontent.com/x",
  // Формы одного и того же законного адреса, на которых наивная проверка
  // строки спотыкается в другую сторону — ложный отказ тоже баг.
  "https://googleapis.com/upload/drive/v3/files?upload_id=X", // апекс без www
  "https://www.googleapis.com:443/upload/drive/v3/files?upload_id=X", // явный стандартный порт
  "https://www.googleapis.com./upload/drive/v3/files?upload_id=X", // точка в конце имени — тот же хост
];
for (const u of ALLOWED) {
  check(`принимает ${u.slice(0, 48)}…`, throws(() => assertAllowedGoogleUrl(u)) === null, String(throws(() => assertAllowedGoogleUrl(u))));
}

const BLOCKED = {
  "http://169.254.169.254/latest/meta-data/": "метаданные облака (AWS link-local)",
  "http://169.254.169.254/computeMetadata/v1/": "метаданные GCP",
  "http://metadata.google.internal/computeMetadata/v1/": "имя метаданных GCP",
  "https://metadata.google.internal/computeMetadata/v1/": "имя метаданных GCP по https",
  "http://localhost:8080/": "локальный хост",
  "http://127.0.0.1/": "loopback",
  "https://127.0.0.1/": "loopback по https",
  "http://[::1]/": "loopback IPv6",
  "https://[::1]/": "loopback IPv6 по https",
  "http://10.0.0.5/internal": "приватный диапазон 10/8",
  "https://192.168.1.1/": "приватный диапазон 192.168/16",
  "https://172.16.5.5/": "приватный диапазон 172.16/12",
  "https://100.64.0.1/": "CGNAT 100.64/10",
  "http://www.googleapis.com/upload/x": "правильный хост, но http",
  "https://www.googleapis.com.evil.example/x": "похожий хост-подделка (суффикс)",
  "https://evil-googleapis.com/upload/drive/v3/files": "похожий хост-подделка (префикс, без точки)",
  "https://evil.example.com/googleapis.com/upload": "разрешённое имя спрятано в ПУТИ чужого хоста",
  "https://www.googleapis.com@evil.test/upload/drive/v3/files": "разрешённое имя как логин, хост чужой",
  "https://evil.example/?redir=https://www.googleapis.com": "чужой хост, Google только в query",
  "https://www.googleapis.com:8443/x": "нестандартный порт",
  "https://user:pass@www.googleapis.com/x": "встроенные учётные данные",
  "file:///etc/passwd": "локальный файл",
  "gopher://www.googleapis.com/": "чужая схема",
};
for (const [u, why] of Object.entries(BLOCKED)) {
  check(`отклоняет ${u.slice(0, 52)} (${why})`, throws(() => assertAllowedGoogleUrl(u)) !== null, "прошёл!");
}
check(
  "ошибка — это BlockedUrlError (отличима от сетевой)",
  (() => {
    try {
      assertAllowedGoogleUrl("http://127.0.0.1/");
      return false;
    } catch (e) {
      return e instanceof BlockedUrlError;
    }
  })(),
);

// ── 2. классификация IP ─────────────────────────────────────────────────────

console.log("\n[2] isBlockedIp — приватное/локальное/служебное против публичного");
const MUST_BLOCK = [
  "127.0.0.1", "127.1.2.3", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.255",
  "192.168.0.1", "169.254.169.254", "169.254.0.1", "100.64.0.1", "224.0.0.1",
  "255.255.255.255", "::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254",
  "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:7f00:1", "ff02::1",
  "not-an-ip", "",
];
for (const ip of MUST_BLOCK) check(`блокирует ${ip || "(пустая строка)"}`, isBlockedIp(ip) === true, "пропустил!");

const MUST_ALLOW = ["8.8.8.8", "142.250.72.14", "172.32.0.1", "100.128.0.1", "2607:f8b0:4005::200e", "2606:4700::1111"];
for (const ip of MUST_ALLOW) check(`пропускает публичный ${ip}`, isBlockedIp(ip) === false, "заблокировал");

// ── 3. адрес реального соединения (подмена разрешения имени) ────────────────

console.log("\n[3] подмена разрешения имени: имя из allowlist, а адрес — приватный");

let hits = 0;
const local = http.createServer((_req, res) => {
  hits++;
  res.end("secret-from-internal-network");
});
await new Promise((r) => local.listen(0, "127.0.0.1", r));
const port = local.address().port;

/** Счётчик реальных исходящих вызовов — доказывает, что до транспорта дело
 * не дошло вовсе, а не «дошло, но ответ выкинули». */
function countingFetch(inner = async () => ({ status: 200, ok: true, headers: { get: () => null }, text: async () => "" })) {
  const state = { n: 0 };
  return {
    state,
    impl: async (...args) => {
      state.n++;
      return inner(...args);
    },
  };
}

// 3a. прямой адрес localhost — отсекается ещё разбором адреса (рубеж 1)
hits = 0;
{
  const { state, impl } = countingFetch();
  let err = null;
  try {
    await safeGoogleFetch(`http://127.0.0.1:${port}/latest/meta-data/`, {}, { fetchImpl: impl });
  } catch (e) {
    err = e;
  }
  check("прямой запрос на 127.0.0.1 отклонён", err instanceof BlockedUrlError, String(err));
  check("транспорт не вызывался ни разу", state.n === 0, String(state.n));
  check("локальный сервер не получил запроса", hits === 0, String(hits));
}

// 3b. имя из allowlist, но резолвится в 127.0.0.1 (классическая подмена).
// Строковая проверка такого не видит — ловит именно рубеж 2.
hits = 0;
for (const [addr, why] of [
  ["127.0.0.1", "loopback"],
  ["169.254.169.254", "метаданные облака"],
  ["10.0.0.7", "приватный диапазон"],
  ["::1", "loopback IPv6"],
]) {
  const { state, impl } = countingFetch();
  let err = null;
  try {
    await safeGoogleFetch(
      "https://www.googleapis.com/upload/drive/v3/files?upload_id=S1",
      { method: "PUT" },
      { fetchImpl: impl, lookup: async () => [{ address: addr }] },
    );
  } catch (e) {
    err = e;
  }
  check(`имя googleapis.com → ${addr} (${why}) отклонено`, err instanceof BlockedUrlError, String(err));
  check(`  …транспорт не вызывался (${addr})`, state.n === 0, String(state.n));
}
check("локальный сервер по-прежнему не получил запроса", hits === 0, String(hits));

// 3c. «отравлен» лишь ОДИН адрес из нескольких — всё равно отказ (fail-closed)
{
  const { state, impl } = countingFetch();
  let err = null;
  try {
    await safeGoogleFetch(
      "https://www.googleapis.com/x",
      {},
      { fetchImpl: impl, lookup: async () => [{ address: "142.250.72.14" }, { address: "10.0.0.5" }] },
    );
  } catch (e) {
    err = e;
  }
  check("смешанный ответ DNS (публичный + приватный) отклонён", err instanceof BlockedUrlError, String(err));
  check("  …транспорт не вызывался", state.n === 0, String(state.n));
}

// 3d. имя не резолвится вообще — тоже отказ, а не «пойдём наугад»
{
  const { state, impl } = countingFetch();
  let err = null;
  try {
    await safeGoogleFetch("https://www.googleapis.com/x", {}, { fetchImpl: impl, lookup: async () => [] });
  } catch (e) {
    err = e;
  }
  check("имя без адресов отклонено (fail-closed)", err instanceof BlockedUrlError, String(err));
  check("  …транспорт не вызывался", state.n === 0, String(state.n));
}

// 3e. публичный адрес проходит — иначе проверка была бы просто «всё запрещено»
{
  const { state, impl } = countingFetch(async () => ({
    status: 200,
    ok: true,
    headers: { get: () => null },
    text: async () => "ok",
  }));
  const res = await safeGoogleFetch(
    "https://www.googleapis.com/x",
    {},
    { fetchImpl: impl, lookup: async () => [{ address: "142.250.72.14" }] },
  );
  check("публичный адрес пропускается", res.status === 200 && state.n === 1, `${res.status}/${state.n}`);
}

// 3f. pinnedLookup структурно неспособен на повторный резолв: его спрашивают
// про ДРУГОЕ имя (которое к этому моменту уже «перевесили» на 127.0.0.1), а он
// всё равно отвечает только проверенным адресом.
{
  const vetted = [{ address: "142.250.72.14", family: 4 }];
  const fn = pinnedLookup(vetted);
  const all = await new Promise((resolve) =>
    fn("attacker-controlled-by-now.example", { all: true }, (err, addrs) => resolve({ err, addrs })),
  );
  check(
    "pinnedLookup (all:true) отдаёт только проверенный адрес",
    all.err === null && all.addrs.length === 1 && all.addrs[0].address === "142.250.72.14",
    JSON.stringify(all),
  );
  const single = await new Promise((resolve) =>
    fn("attacker-controlled-by-now.example", {}, (err, address, family) => resolve({ err, address, family })),
  );
  check(
    "pinnedLookup (одноадресная форма) отдаёт проверенный адрес",
    single.err === null && single.address === "142.250.72.14" && single.family === 4,
    JSON.stringify(single),
  );
  check("pinnedLookup не обращается к dns/net (структурно)", !/dns\.|net\.lookup/.test(fn.toString()), fn.toString().slice(0, 120));
}

local.close();

// ── 4. перенаправления ──────────────────────────────────────────────────────

console.log("\n[4] перенаправления проверяются, а не выполняются вслепую");

/** Заглушка транспорта: отдаёт заранее заданные ответы по очереди. */
function stubFetch(responses) {
  const seen = [];
  const impl = async (url) => {
    seen.push(String(url));
    const r = responses[seen.length - 1];
    if (!r) throw new Error(`неожиданный лишний запрос: ${url}`);
    return {
      status: r.status,
      ok: r.status >= 200 && r.status < 300,
      headers: { get: (k) => r.headers?.[k.toLowerCase()] ?? null },
      text: async () => r.body ?? "",
      json: async () => JSON.parse(r.body ?? "{}"),
    };
  };
  return { impl, seen };
}

const START = "https://www.googleapis.com/upload/drive/v3/files?upload_id=S1";
const publicLookup = async () => [{ address: "142.250.72.14" }];

for (const [label, location] of [
  ["на метаданные облака", "http://169.254.169.254/latest/meta-data/"],
  ["на localhost", "http://127.0.0.1:1/"],
  ["на приватный диапазон", "http://10.0.0.7/internal"],
  ["на чужой хост", "https://evil.example/steal"],
  ["на похожий хост-подделку", "https://www.googleapis.com.evil.example/steal"],
]) {
  const { impl, seen } = stubFetch([{ status: 302, headers: { location } }]);
  let e = null;
  try {
    await safeGoogleFetch(START, { method: "PUT" }, { fetchImpl: impl, lookup: publicLookup });
  } catch (caught) {
    e = caught;
  }
  check(`редирект ${label} отклонён`, e instanceof BlockedUrlError, String(e));
  check(`  …второго запроса не было (${label})`, seen.length === 1, seen.join(" → "));
}

{
  // редирект на разрешённый хост, который резолвится в приватный адрес —
  // рубеж 2 обязан отработать и на КАЖДОМ переходе, не только на первом
  let calls = 0;
  const flipFlopLookup = async () => (++calls === 1 ? [{ address: "142.250.72.14" }] : [{ address: "169.254.169.254" }]);
  const { impl, seen } = stubFetch([
    { status: 302, headers: { location: "https://storage.googleapis.com/next" } },
    { status: 200, body: "SHOULD NOT REACH" },
  ]);
  let e = null;
  try {
    await safeGoogleFetch(START, {}, { fetchImpl: impl, lookup: flipFlopLookup });
  } catch (caught) {
    e = caught;
  }
  check("редирект на разрешённый хост с приватным адресом отклонён", e instanceof BlockedUrlError, String(e));
  check("  …второго запроса не было", seen.length === 1, seen.join(" → "));
}

{
  // относительный Location на том же разрешённом хосте — можно идти дальше
  const { impl, seen } = stubFetch([
    { status: 302, headers: { location: "/upload/drive/v3/files?upload_id=S2" } },
    { status: 200, body: '{"id":"NEW"}' },
  ]);
  const res = await safeGoogleFetch(START, { method: "PUT" }, { fetchImpl: impl, lookup: publicLookup });
  check("редирект внутри googleapis.com выполняется", res.status === 200, String(res.status));
  check("второй запрос ушёл на разрешённый адрес", seen[1]?.startsWith("https://www.googleapis.com/"), seen.join(" → "));
}

{
  // 308 от Google — это «Resume Incomplete», а НЕ перенаправление
  const { impl, seen } = stubFetch([{ status: 308, headers: { range: "bytes=0-524287" } }]);
  const res = await safeGoogleFetch(START, { method: "PUT" }, { fetchImpl: impl, lookup: publicLookup });
  check("308 без Location отдаётся как есть (статус загрузки)", res.status === 308, String(res.status));
  check("308 не порождает второго запроса", seen.length === 1, seen.join(" → "));
}

{
  // цепочка редиректов не бесконечна
  const chain = Array.from({ length: 6 }, () => ({ status: 302, headers: { location: START } }));
  const { impl, seen } = stubFetch(chain);
  let e = null;
  try {
    await safeGoogleFetch(START, {}, { fetchImpl: impl, lookup: publicLookup, maxRedirects: 2 });
  } catch (caught) {
    e = caught;
  }
  check("цепочка редиректов обрывается по лимиту", e instanceof BlockedUrlError, String(e));
  check("лимит соблюдён (3 запроса при maxRedirects=2)", seen.length === 3, String(seen.length));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
