#!/usr/bin/env node
/**
 * Режим «исполнение ТОЛЬКО кнопкой» (`isTgButtonOnly` + ветка (3.4) в
 * `requireConsent`) — перенос из python-эталона ticktick-mcp (PR #17) по
 * КОНТРАКТУ, а не копированием кода: здесь манифесты живут в Postgres, поэтому
 * «план ушёл кнопкой» — это поле записи манифеста (`tgNotified`), переживающее
 * рестарт, а не флаг в RAM.
 *
 * Суть: если план реально ушёл кнопкой И по нажатию есть чем его исполнить —
 * текстовое подтверждение для этого плана закрывается СОВСЕМ. Дыру «модель
 * сочиняет согласие за человека» это устраняет, а не уменьшает.
 *
 * Запуск: node scripts/test-tg-button-only.mjs
 */
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { requireConsent, tryAutoExecute, isTgButtonOnly, sha256 } from "../src/consent.ts";
import { registeredAutoExecuteTools } from "../dist/autoExecute.js";
import { registerGmailTools } from "../dist/tools/gmail.js"; // + регистрация авто-исполнителей на уровне модуля

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};

const clock = { t: 1_700_000_000_000 };
const now = () => clock.t;
const cfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now };

const PAYLOAD = { account: "work", messages: [{ to: "eric@x.com", subject: "Q", body: "..." }] };
const OBJHASH = sha256(PAYLOAD);
const plan = () => ({ payload: PAYLOAD, objectHash: OBJHASH, preview: "### 📤 План отправки", batchSize: 1 });
const rehash = (addressing) => sha256(addressing);

function makeStore() {
  const manifests = new Map();
  const audits = [];
  return {
    manifests,
    audits,
    async createManifest(input) {
      manifests.set(input.id, { ...input, status: "AWAITING_CONSENT", consumedAt: null, userReply: null, tgNotified: false });
    },
    async getManifest(id, server) {
      const r = manifests.get(id);
      return r && r.server === server ? { ...r } : null;
    },
    async consumeManifest(id, server, userReply) {
      const r = manifests.get(id);
      if (!r || r.server !== server || r.status !== "AWAITING_CONSENT" || clock.t >= r.expiresAt) return null;
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
    async markTgNotified(id, server) {
      const r = manifests.get(id);
      if (r && r.server === server && r.status === "AWAITING_CONSENT") r.tgNotified = true;
    },
    async appendConsentAudit(entry) {
      audits.push({ ...entry });
    },
    async updateConsentAuditOutcome() {},
  };
}

/** Фейковый ТГ-слой со счётчиками вызовов — счётчик `checkApproval` нужен,
 * чтобы доказать, что при выключенном слое к нему НЕ ходили ни разу. */
function makeTg({ enabled = true, approval = "pending", sendOk = true } = {}) {
  const calls = { enabledFor: 0, notifyPlan: 0, checkApproval: 0 };
  return {
    calls,
    setApproval(v) {
      approval = v;
    },
    setEnabled(v) {
      enabled = v;
    },
    enabledFor() {
      calls.enabledFor++;
      return enabled;
    },
    async notifyPlan() {
      calls.notifyPlan++;
      return sendOk ? { ok: true } : { ok: false, error: "boom" };
    },
    async checkApproval() {
      calls.checkApproval++;
      return approval;
    },
  };
}

const HAS_EXECUTOR = () => true;
const NO_EXECUTOR = () => false;

/** План через настоящий `requireConsent` (а не подкладывание строки в стор) —
 * так проверяется и то, что метка `tgNotified` ставится реальным кодом. */
async function buildPlan({ tg, hasAutoExecutor } = {}) {
  const store = makeStore();
  clock.t = 1_700_000_000_000;
  const dec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg, tg, hasAutoExecutor,
  });
  return { store, dec, id: dec.manifestId };
}

// ═══ [1] юнит формулы ══════════════════════════════════════════════════════
console.log("[1] формула isTgButtonOnly — две строки, никаких списков имён тулов");
{
  check("нет метки → false", isTgButtonOnly({ tool: "gmail_send", tgNotified: false }, HAS_EXECUTOR) === false);
  check("метка undefined → false", isTgButtonOnly({ tool: "gmail_send" }, HAS_EXECUTOR) === false);
  check("метка есть, исполнителя нет → false (мягкая деградация в текстовый путь)",
    isTgButtonOnly({ tool: "gmail_send", tgNotified: true }, NO_EXECUTOR) === false);
  check("метка + исполнитель → true", isTgButtonOnly({ tool: "gmail_send", tgNotified: true }, HAS_EXECUTOR) === true);
  check("hasAutoExecutor вообще не передан → false (переносимость на серверы без реестра)",
    isTgButtonOnly({ tool: "gmail_send", tgNotified: true }) === false);
}

// ═══ [2] метка ставится ровно там, где отправка удалась ════════════════════
console.log("\n[2] `tgNotified` ставится ТОЛЬКО после успешной отправки кнопок");
{
  const noTg = await buildPlan({ hasAutoExecutor: HAS_EXECUTOR });
  check("TG-слой не подключён → метки нет", noTg.store.manifests.get(noTg.id).tgNotified === false);

  const okTg = await buildPlan({ tg: makeTg(), hasAutoExecutor: HAS_EXECUTOR });
  check("отправка удалась → метка стоит", okTg.store.manifests.get(okTg.id).tgNotified === true);
  check("приписка к плану говорит «ТОЛЬКО кнопкой»", /ТОЛЬКО кнопкой/.test(okTg.dec.preview), okTg.dec.preview);
  check("приписка НЕ просит текстовое «да»", !/ответьте «да»/.test(okTg.dec.preview), okTg.dec.preview);

  const noExec = await buildPlan({ tg: makeTg(), hasAutoExecutor: NO_EXECUTOR });
  check("зеркально: план без авто-исполнителя честно просит ПОВТОРИТЬ вызов",
    /повтори вызов инструмента/.test(noExec.dec.preview), noExec.dec.preview);

  const failed = await buildPlan({ tg: makeTg({ sendOk: false }), hasAutoExecutor: HAS_EXECUTOR });
  check("отправка упала → fail-closed: план убит", failed.store.manifests.get([...failed.store.manifests.keys()][0]).status === "INVALIDATED");
  check("отправка упала → метка НЕ поставлена", failed.store.manifests.get([...failed.store.manifests.keys()][0]).tgNotified === false);
}

// ═══ [3] pending: текстовое «да» больше не исполняет ═══════════════════════
console.log("\n[3] кнопка ещё не нажата → любое текстовое «да» ничего не исполняет");
{
  const tg = makeTg({ approval: "pending" });
  const { store, id } = await buildPlan({ tg, hasAutoExecutor: HAS_EXECUTOR });
  clock.t += 6_000;
  const dec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg,
    tg, hasAutoExecutor: HAS_EXECUTOR,
  });
  check("→ refused", dec.kind === "refused", dec.kind);
  check("план ЖИВ", store.manifests.get(id).status === "AWAITING_CONSENT", store.manifests.get(id).status);
  check("в ответе есть 🛑", /🛑/.test(dec.result));
  check("ответ говорит про кнопку", /кнопк/i.test(dec.result), dec.result);
  check("ответ говорит, что текстовое подтверждение отключено", /отключено/.test(dec.result), dec.result);
  check("аудит помечает режим button-only", store.audits.at(-1)?.checks?.tgButtonOnly === "yes", JSON.stringify(store.audits.at(-1)?.checks));
}

// ═══ [4] содержание реплики больше не влияет НИ НА ЧТО ════════════════════
console.log("\n[4] разные реплики → ОДИНАКОВЫЙ отказ (суть фикса)");
{
  const results = [];
  for (const reply of ["да", "давай, подтверждаю", "ага, делай", "ок"]) {
    const tg = makeTg({ approval: "pending" });
    const { store, id } = await buildPlan({ tg, hasAutoExecutor: HAS_EXECUTOR });
    clock.t += 6_000;
    const dec = await requireConsent({
      tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: reply, plan, rehash, store, cfg,
      tg, hasAutoExecutor: HAS_EXECUTOR,
    });
    results.push(dec.result);
    check(`«${reply}» → refused, план жив`, dec.kind === "refused" && store.manifests.get(id).status === "AWAITING_CONSENT", dec.kind);
  }
  check("все четыре ответа ПОБУКВЕННО одинаковы", new Set(results).size === 1, String(new Set(results).size));

  // Пустая реплика в этом репозитории отсекается РАНЬШЕ (пара
  // manifest_id+user_reply неполна) — отказ другой по тексту, но последствие
  // то же: ничего не исполнено, план жив.
  const tg = makeTg({ approval: "pending" });
  const { store, id } = await buildPlan({ tg, hasAutoExecutor: HAS_EXECUTOR });
  clock.t += 6_000;
  const empty = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "", plan, rehash, store, cfg,
    tg, hasAutoExecutor: HAS_EXECUTOR,
  });
  check("пустая реплика → refused, план жив", empty.kind === "refused" && store.manifests.get(id).status === "AWAITING_CONSENT", empty.kind);
}

// ═══ [5] approved: отказ текстовому пути, но манифест НЕ гасим ═════════════
console.log("\n[5] кнопка нажата, фоновый исполнитель ещё не добрался");
{
  const tg = makeTg({ approval: "approved" });
  const { store, id } = await buildPlan({ tg, hasAutoExecutor: HAS_EXECUTOR });
  clock.t += 6_000;
  const dec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg,
    tg, hasAutoExecutor: HAS_EXECUTOR,
  });
  check("→ refused (сервер исполняет сам)", dec.kind === "refused", dec.kind);
  check("ответ говорит «уже подтверждено кнопкой»", /Уже подтверждено кнопкой/.test(dec.result), dec.result);
  check("КРИТИЧНО: манифест НЕ погашен", store.manifests.get(id).status === "AWAITING_CONSENT", store.manifests.get(id).status);

  // обратная сторона того же требования: операция не потеряна — фоновый
  // исполнитель находит план и реально его исполняет
  const auto = await tryAutoExecute({ manifestId: id, tool: "gmail_send", accountLabel: "work" }, rehash, store, cfg);
  check("фоновый исполнитель нашёл план и исполнил", auto !== null && auto.manifestId === id);
  check("манифест погашен уже ИМ", store.manifests.get(id).status === "DONE", store.manifests.get(id).status);

  // идемпотентность: повторный текстовый вызов после исполнения
  clock.t += 1_000;
  const again = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg,
    tg, hasAutoExecutor: HAS_EXECUTOR,
  });
  check("повтор → refused", again.kind === "refused", again.kind);
  check("повтор: внятное «уже исполнено кнопкой»", /Уже исполнено кнопкой/.test(again.result), again.result);
  check("повтор: операция НЕ продублирована (один аудит confirmed)",
    store.audits.filter((a) => a.outcome === "confirmed").length === 1,
    String(store.audits.filter((a) => a.outcome === "confirmed").length));
}

// ═══ [6] rejected → план сожжён ════════════════════════════════════════════
console.log("\n[6] кнопка «Отклонить» → план сожжён");
{
  const tg = makeTg({ approval: "rejected" });
  const { store, id } = await buildPlan({ tg, hasAutoExecutor: HAS_EXECUTOR });
  clock.t += 6_000;
  const dec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg,
    tg, hasAutoExecutor: HAS_EXECUTOR,
  });
  check("→ refused", dec.kind === "refused", dec.kind);
  check("план INVALIDATED", store.manifests.get(id).status === "INVALIDATED", store.manifests.get(id).status);
}

// ═══ [7] решение по СОСТОЯНИЮ ПЛАНА, а не по текущей настройке ═════════════
// Тест, который РАЗЛИЧАЕТ две реализации: план ушёл кнопкой → настройку
// выключили → текстовый путь обязан остаться закрытым. Реализация, читающая
// текущий TG_APPROVAL_ENABLED/`enabledFor()`, здесь бы ИСПОЛНИЛА операцию.
console.log("\n[7] выключение TG-слоя ПОСЛЕ отправки плана не открывает текстовый путь");
{
  const tg = makeTg({ approval: "approved" });
  const { store, id } = await buildPlan({ tg, hasAutoExecutor: HAS_EXECUTOR });
  tg.setEnabled(false); // «слой выключили между планом и исполнением»
  clock.t += 6_000;
  const dec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg,
    tg, hasAutoExecutor: HAS_EXECUTOR,
  });
  check("→ refused (текстовый путь всё ещё закрыт)", dec.kind === "refused", dec.kind);
  check("манифест не исполнен текстом", store.manifests.get(id).status === "AWAITING_CONSENT", store.manifests.get(id).status);

  // тот же сценарий, но слой вырезан совсем (сервер перезапущен без Telegram):
  // fail-closed — план, ушедший кнопкой, текстом не исполняется всё равно
  const { store: s2, id: id2 } = await buildPlan({ tg: makeTg(), hasAutoExecutor: HAS_EXECUTOR });
  clock.t += 6_000;
  const dec2 = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: id2, userReply: "да", plan, rehash, store: s2, cfg,
    hasAutoExecutor: HAS_EXECUTOR, // tg НЕ передан вовсе
  });
  check("tg вырезан → всё равно refused (fail-closed)", dec2.kind === "refused", dec2.kind);
  check("манифест жив", s2.manifests.get(id2).status === "AWAITING_CONSENT", s2.manifests.get(id2).status);
}

// ═══ [8] при выключенном Telegram-слое всё работает как раньше ═════════════
console.log("\n[8] TG-слой выключен → обычный текстовый путь нетронут");
{
  const tg = makeTg({ enabled: false });
  const { store, id } = await buildPlan({ tg, hasAutoExecutor: HAS_EXECUTOR });
  check("метка не поставлена (кнопки не отправлялись)", store.manifests.get(id).tgNotified === false);
  check("notifyPlan не вызывался", tg.calls.notifyPlan === 0, String(tg.calls.notifyPlan));
  clock.t += 6_000;
  const dec = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: id, userReply: "да", plan, rehash, store, cfg,
    tg, hasAutoExecutor: HAS_EXECUTOR,
  });
  check("текстовое «да» ИСПОЛНЯЕТ", dec.kind === "confirmed", dec.kind);
  check("checkApproval не вызывался НИ РАЗУ", tg.calls.checkApproval === 0, String(tg.calls.checkApproval));

  const tg2 = makeTg({ enabled: false });
  const { store: s2, id: id2 } = await buildPlan({ tg: tg2, hasAutoExecutor: HAS_EXECUTOR });
  clock.t += 6_000;
  const dec2 = await requireConsent({
    tool: "gmail_send", accountLabel: "work", manifestId: id2, userReply: "нет, отмена", plan, rehash, store: s2, cfg,
    tg: tg2, hasAutoExecutor: HAS_EXECUTOR,
  });
  check("«нет, отмена» по-прежнему отказ", dec2.kind === "refused", dec2.kind);
  check("«нет, отмена» по-прежнему сжигает план", s2.manifests.get(id2).status === "INVALIDATED", s2.manifests.get(id2).status);
}

// ═══ [9] инвентаризация: у каждого «кнопочного» тула есть чем исполниться ══
console.log("\n[9] инвентаризация: гейтованные тулы vs реестр авто-исполнителей");
{
  // Список гейтованных тулов строится СКАНОМ ИСХОДНИКА, а не хардкодом: иначе
  // новый тул, добавленный в gmail.ts, молча не попал бы под проверку.
  const src = readFileSync(new URL("../src/tools/gmail.ts", import.meta.url), "utf8");
  const gated = [...src.matchAll(/await requireGmailConsent<[^>]*>\(\{\s*tool:\s*"([^"]+)"/g)].map((m) => m[1]);
  // Нижняя граница — иначе сломанный скан (regex перестал матчиться) молча
  // прошёл бы по ПУСТОМУ множеству и тест был бы «зелёным» ни на чём.
  check(`скан нашёл гейтованные тулы (${gated.length} ≥ 15)`, gated.length >= 15, String(gated.length));
  check("скан не нашёл дублей", new Set(gated).size === gated.length, gated.join(","));

  const registered = new Set(registeredAutoExecuteTools());
  check(`реестр авто-исполнителей непуст (${registered.size} ≥ 15)`, registered.size >= 15, String(registered.size));

  /** Поимённые исключения — тул, чей план уходит кнопкой, но исполнить его по
   * нажатию нечем. Пусто: после T1 все 15 переведены на авто-исполнение.
   * Каждая будущая запись обязана нести причину. */
  const NO_EXECUTOR_ALLOWLIST = {};
  const missing = (list) => list.filter((t) => !registered.has(t) && !(t in NO_EXECUTOR_ALLOWLIST));
  check("у КАЖДОГО гейтованного тула есть авто-исполнитель", missing(gated).length === 0, missing(gated).join(", "));

  // Мутационный тест САМОЙ инвентаризации: выкидываем один тул из реестра —
  // проверка обязана покраснеть. Без этого «зелёная инвентаризация» ничего не
  // доказывает (сломанный скан/пустой реестр выглядели бы точно так же).
  const dropped = gated[0];
  registered.delete(dropped);
  check(`мутация: без «${dropped}» в реестре инвентаризация краснеет`, missing(gated).length === 1, missing(gated).join(", "));
  registered.add(dropped);
  check("после отката мутации инвентаризация снова зелёная", missing(gated).length === 0);
}

// ═══ [10] СКВОЗЬ РЕАЛЬНЫЙ MCP-ПУТЬ ═══════════════════════════════════════
// Все проверки выше зовут `requireConsent` напрямую и сами передают
// `hasAutoExecutor` — то есть они НЕ доказывают, что боевой код (`gmail.ts`)
// это условие вообще прокидывает. Мутационная проверка это и показала: если
// удалить прокидку из обёртки `requireGmailConsent`, наборы [1]–[9] остаются
// зелёными, а в проде режим «только кнопкой» тихо выключается для ВСЕХ тулов.
// Поэтому здесь — настоящий тул через настоящий MCP-реестр.
console.log("\n[10] сквозной путь через реальный gmail_send (боевая проводка hasAutoExecutor)");
{
  const counters = { send: 0 };
  const clients = {
    names: ["work"], defaultName: "work", multi: false,
    resolve: () => ({
      gmail: {
        users: {
          getProfile: async () => ({ data: { emailAddress: "me@x.com" } }),
          messages: {
            send: async () => { counters.send++; return { data: { id: "SID", threadId: "T1" } }; },
            get: async () => ({ data: { labelIds: ["SENT"], payload: { headers: [] } } }),
            list: async () => ({ data: { resultSizeEstimate: 0 } }),
          },
        },
      },
      accessToken: async () => "fake-token",
    }),
    canonicalName: (n) => (n && n.trim() ? n.trim() : "work"),
    emailFor: () => "me@x.com",
    baseGmailQuery: () => "",
  };

  clock.t = 1_700_000_000_000;
  const tg = makeTg({ approval: "pending" });
  const store = makeStore();
  const server = new McpServer({ name: "button-only", version: "0" });
  registerGmailTools(server, clients, {
    store: null, userToken: null, consentStore: store, consentCfg: cfg, auditStore: null, tg,
  });
  const cli = new Client({ name: "c", version: "0" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(b), cli.connect(a)]);

  const planRes = await cli.callTool({ name: "gmail_send", arguments: { messages: [{ to: "a@x.com", subject: "S", body: "B" }] } });
  const planText = planRes.content[0].text;
  const manifestId = planText.match(/план `([^`]+)`/)?.[1];
  check("план построен и метка кнопки проставлена боевым кодом",
    !!manifestId && store.manifests.get(manifestId)?.tgNotified === true,
    JSON.stringify(store.manifests.get(manifestId)));
  check("приписка боевого плана: «ТОЛЬКО кнопкой»", /ТОЛЬКО кнопкой/.test(planText), planText.slice(-200));

  clock.t += 6_000;
  const execText = (await cli.callTool({ name: "gmail_send", arguments: { manifest_id: manifestId, user_reply: "да, отправляй" } })).content[0].text;
  check("боевой gmail_send: текстовое «да» НЕ отправило письмо", counters.send === 0, String(counters.send));
  check("боевой gmail_send: отказ говорит про кнопку", /кнопк/i.test(execText), execText.slice(0, 160));
  check("боевой gmail_send: план жив", store.manifests.get(manifestId).status === "AWAITING_CONSENT", store.manifests.get(manifestId).status);

  // Самый прямой снимок дыры: кнопка УЖЕ нажата. Без режима «только кнопкой»
  // текстовое «да» здесь ОТПРАВИЛО БЫ письмо (модель могла бы сочинить это
  // «да» сама); с ним — письмо отправит сервер, по нажатию, а текстовый путь
  // молча ничего не делает.
  tg.setApproval("approved");
  clock.t += 1_000;
  const approvedText = (await cli.callTool({ name: "gmail_send", arguments: { manifest_id: manifestId, user_reply: "да, отправляй" } })).content[0].text;
  check("кнопка нажата: текстовое «да» всё равно НЕ отправило письмо", counters.send === 0, String(counters.send));
  check("кнопка нажата: ответ — «уже подтверждено кнопкой»", /Уже подтверждено кнопкой/.test(approvedText), approvedText.slice(0, 160));
  check("кнопка нажата: манифест НЕ погашен (его заберёт фоновый исполнитель)",
    store.manifests.get(manifestId).status === "AWAITING_CONSENT", store.manifests.get(manifestId).status);
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
