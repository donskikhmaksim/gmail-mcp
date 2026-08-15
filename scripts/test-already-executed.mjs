#!/usr/bin/env node
/**
 * Исход `already_executed` (2026-08-14) — подтверждение пришло ВНЕ этого
 * вызова (веб-хаб `/pending-consents/decide` или кнопка в Telegram) во время
 * синхронного ожидания.
 *
 * ЧТО ИМЕННО ЛЕЧИТСЯ. Максим: «подтверждаю в портале за 2 секунды, запрос
 * оттуда исчезает, а Claude не понимает, что всё сделано, и шлёт запрос
 * заново — и так несколько кругов». Причина: этот положительный исход ехал в
 * форме `{kind:"refused"}` с позитивным текстом внутри, и тул отдавал его как
 * `okVerbatim(..., "refusal")` — в `_meta` модели уходила машинная метка
 * «отказ» при тексте «✅ Подтверждено и исполнено». Модель верит метке, а не
 * прозе.
 *
 * ЧТО НЕЛЬЗЯ СЛОМАТЬ, чиня это: мутацию к этому моменту УЖЕ исполнил другой
 * канал (веб-хаб делает `tryAutoExecute` + `executor.execute` синхронно внутри
 * своего HTTP-запроса). Вернуть отсюда `confirmed` = отправить второе письмо.
 * Поэтому у нового исхода нет поля `payload` вообще — тесты 1 и 5 проверяют
 * именно это, а не только «kind поменялся».
 *
 * Файл держит и статическую проверку call site'ов (тест 6): текст отчёта
 * бесполезен, если хоть один тул отдаёт его под меткой "refusal".
 *
 * Запуск: node scripts/test-already-executed.mjs
 */
import { readFileSync, readdirSync } from "node:fs";
import { requireConsent, sha256 } from "../src/consent.ts";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

const clock = { t: 1_700_000_000_000 };
const now = () => clock.t;

/** Фейковый стор: тот же контракт, что у `consentStoreAdapter` в server.ts,
 * включая ОПЦИОНАЛЬНЫЙ `getAuditByManifest` (его подключение — часть фикса:
 * без него ветка честно скажет «перепроверить не удалось», тест 3). */
function makeStore({ withAudit = true } = {}) {
  const manifests = new Map();
  const audits = [];
  const calls = { consume: 0, audit: 0 };
  const store = {
    manifests,
    audits,
    calls,
    async createManifest(input) {
      manifests.set(input.id, { ...input, status: "AWAITING_CONSENT", consumedAt: null, userReply: null });
    },
    async getManifest(id, server) {
      const r = manifests.get(id);
      if (!r || r.server !== server) return null;
      return { ...r };
    },
    async consumeManifest(id, server, userReply) {
      calls.consume++;
      const r = manifests.get(id);
      if (!r || r.server !== server || r.status !== "AWAITING_CONSENT") return null;
      if (clock.t >= r.expiresAt) return null;
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
    async appendConsentAudit(entry) {
      audits.push({ ...entry });
    },
    async updateConsentAuditOutcome(auditId, outcome) {
      const a = audits.find((x) => x.id === auditId);
      if (a) Object.assign(a, { postVerifyResult: outcome.postVerify ?? a.postVerifyResult, ...outcome });
    },
  };
  if (withAudit) {
    // Тот же порядок, что у SQL-реализации в store.ts: сначала строка с уже
    // записанным пруфом, потом просто самая свежая.
    store.getAuditByManifest = async (manifestId, server) => {
      calls.audit++;
      const rows = audits.filter((a) => a.manifestId === manifestId && a.server === server);
      if (!rows.length) return null;
      const withProof = rows.filter((a) => a.postVerifyResult || a.error);
      const row = (withProof.length ? withProof : rows).at(-1);
      return {
        id: row.id,
        outcome: row.outcome,
        postVerifyResult: row.postVerifyResult ?? null,
        error: row.error ?? null,
      };
    };
  }
  return store;
}

const cfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now };
const syncCfg = { ...cfg, syncWaitMs: 5_000, syncPollMs: 1_000 };

const PAYLOAD = { account: "work", messages: [{ to: "eric@x.com", subject: "Quote", body: "..." }] };
const OBJHASH = sha256(PAYLOAD);
const plan = () => ({
  payload: PAYLOAD,
  objectHash: OBJHASH,
  preview: "### 📤 План отправки\n\n- **Кому:** eric@x.com",
  batchSize: 1,
});
const rehash = (payload) => sha256(payload);

/**
 * Симуляция ВНЕШНЕГО канала (веб-хаб): на 2-й итерации опроса он атомарно
 * потребляет манифест, пишет аудит-строку фазы согласия и — как настоящий
 * `executor.execute` — дописывает в неё реальный пруф post-verify.
 */
function hookExternalConfirm(store, { postVerify, error } = {}) {
  let polls = 0;
  const real = store.getManifest.bind(store);
  store.getManifest = async (id, server) => {
    polls++;
    if (polls === 2) {
      await store.consumeManifest(id, server, "[веб-хаб: подтверждено]");
      const auditId = `audit-${id}`;
      await store.appendConsentAudit({
        id: auditId,
        ts: clock.t,
        server,
        tool: "gmail_send",
        accountLabel: "work",
        manifestId: id,
        objectHash: OBJHASH,
        userReply: "[веб-хаб: подтверждено]",
        checks: { source: "web_hub" },
        outcome: "confirmed",
        actor: "human",
      });
      if (postVerify !== undefined || error !== undefined) {
        await store.updateConsentAuditOutcome(auditId, {
          outcome: error ? "failed" : "confirmed",
          postVerify: postVerify ?? null,
          error: error ?? null,
        });
      }
    }
    return real(id, server);
  };
  return () => polls;
}

console.log("\n[1] подтверждено веб-хабом в окне ожидания → отчёт об исполнении, а НЕ отказ");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  hookExternalConfirm(store, { postVerify: "✉️ Отправлено 1/1 · post-verify: id=18f2ab, кому eric@x.com" });
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg: syncCfg });

  check("kind=already_executed", dec.kind === "already_executed", JSON.stringify(dec).slice(0, 140));
  check("НЕ refused (модель больше не видит машинный «отказ» на успехе)", dec.kind !== "refused");
  check("НЕ confirmed (иначе тул исполнил бы мутацию второй раз)", dec.kind !== "confirmed");
  check("в исходе нет payload — повторить мутацию физически нечем", !("payload" in dec));
  check("manifestId проброшен", dec.manifestId === [...store.manifests.keys()][0]);
  check("auditId проброшен (по нему видно, чей это был исход)", dec.auditId === `audit-${dec.manifestId}`, dec.auditId);
  check(
    "в отчёте есть ФАКТИЧЕСКИЙ результат (id письма из post_verify), а не только «исполнено другим каналом»",
    dec.report.includes("Отправлено 1/1") && dec.report.includes("18f2ab"),
    dec.report.slice(0, 200),
  );
  check("отчёт прямо говорит не повторять вызов", /НЕ нужно/.test(dec.report), dec.report.slice(-200));
  check(
    "requireConsent НЕ потреблял манифест сам (единственный consume — внешнего канала)",
    store.calls.consume === 1,
    store.calls.consume,
  );
  check("манифест DONE", [...store.manifests.values()][0].status === "DONE");
  check(
    "новая аудит-запись НЕ дописана (аудит уже вёл тот, кто исполнил)",
    store.audits.length === 1,
    store.audits.length,
  );
}

console.log("\n[2] исполнение упало на стороне внешнего канала → отчёт честно показывает ошибку");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  hookExternalConfirm(store, { error: "SMTP 550: mailbox unavailable" });
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg: syncCfg });
  check("kind=already_executed", dec.kind === "already_executed", dec.kind);
  check("ошибка исполнения попала в отчёт", dec.report.includes("SMTP 550"), dec.report.slice(-300));
  check("нет payload", !("payload" in dec));
  // Security-review 2026-08-14 (проблема №1): DONE = «манифест захвачен», а
  // не «операция удалась» — заголовок и разрешающая формулировка ОБЯЗАНЫ
  // смотреть на audit.outcome/error, а не только на binding. Воспроизведено
  // проверяющим на этом самом моке: раньше здесь всё равно рисовалось
  // «### ✅ Подтверждено и исполнено».
  check("заголовок НЕ рисует успех при провалившемся исполнении", !dec.report.includes("✅ Подтверждено и исполнено"), dec.report.slice(0, 60));
  check("заголовок явно предупреждает (⚠️/🛑), не тихая галочка", /^### (⚠️|🛑)/.test(dec.report), dec.report.slice(0, 60));
  check(
    "текст требует проверить вручную, а НЕ безусловное «повторять не нужно»",
    /проверь вручную/i.test(dec.report),
    dec.report.slice(0, 600),
  );
}

console.log("\n[2b] ошибка исполнения содержит URL с query (токен доступа) → в ответе модели query вырезан");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  hookExternalConfirm(store, {
    error:
      "fetch failed: https://storage.googleapis.com/bucket/report.pdf?X-Goog-Signature=SECRET123&X-Goog-Expires=900 responded 403",
  });
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg: syncCfg });
  check("query-параметр (токен доступа) вырезан из ответа модели", !dec.report.includes("SECRET123"), dec.report.slice(-500));
  check("host+path URL остались читаемыми (не вся ссылка стёрта)", dec.report.includes("storage.googleapis.com/bucket/report.pdf"), dec.report.slice(-500));
}

console.log("\n[3] пруфа в аудите нет → честное «перепроверить не удалось», а не молчание");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore({ withAudit: false }); // старый адаптер без read-метода
  hookExternalConfirm(store);
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg: syncCfg });
  check("kind=already_executed (ветка не падает без опционального метода)", dec.kind === "already_executed", dec.kind);
  check("сказано, что результат перепроверить не удалось", /перепроверить не удалось/.test(dec.report), dec.report.slice(-300));
  check("но повторять вызов всё равно не предлагается", /НЕ нужно|не нужно/.test(dec.report));
}

console.log("\n[4] отказ через веб в окне ожидания → по-прежнему refused");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  let polls = 0;
  const real = store.getManifest.bind(store);
  store.getManifest = async (id, server) => {
    polls++;
    if (polls === 2) await store.invalidateManifest(id, server, "нет, не то письмо");
    return real(id, server);
  };
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg: syncCfg });
  check("kind=refused (настоящий отказ остаётся отказом)", dec.kind === "refused", dec.kind);
  check("манифест INVALIDATED", [...store.manifests.values()][0].status === "INVALIDATED");
}

console.log("\n[5] никто не ответил за окно → прежнее поведение: превью плана");
{
  clock.t = 1_700_000_000_000;
  const store = makeStore();
  const waitCfg = { ...cfg, syncWaitMs: 2_500, syncPollMs: 1_000 };
  const real = store.getManifest.bind(store);
  store.getManifest = async (id, server) => {
    clock.t += waitCfg.syncPollMs; // мок-часы не текут сами — двигаем к дедлайну
    return real(id, server);
  };
  const dec = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg: waitCfg });
  check("kind=planned", dec.kind === "planned", dec.kind);
  check("манифест жив (AWAITING_CONSENT)", [...store.manifests.values()][0].status === "AWAITING_CONSENT");
  check("аудит-читалка на этом пути не дёргалась", store.calls.audit === 0, store.calls.audit);
}

console.log("\n[6] статика: каждый call site отдаёт already_executed как отчёт, а не как отказ");
{
  const files = readdirSync(new URL("../src/tools/", import.meta.url))
    .filter((f) => f.endsWith(".ts"))
    .map((f) => ["src/tools/" + f, readFileSync(new URL("../src/tools/" + f, import.meta.url), "utf8")]);
  let sites = 0;
  let handled = 0;
  let mislabelled = 0;
  for (const [name, src] of files) {
    const lines = src.split("\n");
    lines.forEach((line, i) => {
      if (!/decision\.kind === "refused"/.test(line)) return;
      sites++;
      const window = lines.slice(Math.max(0, i - 4), i + 5).join("\n");
      if (/decision\.kind === "already_executed"/.test(window)) handled++;
      else console.log(`       не обработан already_executed: ${name}:${i + 1}`);
    });
    for (const m of src.matchAll(/decision\.kind === "already_executed"\)\s*return\s+(\w+)\(decision\.report,\s*"([^"]+)"/g)) {
      if (m[2] === "refusal") mislabelled++;
    }
  }
  check("call site'ы найдены", sites > 0, sites);
  check(`все ${sites} call site'ов обрабатывают already_executed`, handled === sites, `${handled}/${sites}`);
  check("ни один не помечен как \"refusal\"", mislabelled === 0, mislabelled);
}

console.log("\n[7] _meta already_executed идёт под тем же неймспейсом ru.donskikh.mcp/presentation, что и остальные ответы");
{
  // Security-review 2026-08-14 (проблема №2): в этом репо все 17 call site'ов
  // уже отдают already_executed через okVerbatim(decision.report,
  // "execution-report") — тот же общий хелпер util.ts, что и остальные
  // ответы (проверено вручную: ни одного "сырого" `_meta:` мимо util.ts во
  // всём src/). Этот тест закрепляет это структурно, чтобы регресс не
  // проскочил незамеченным.
  // dist/, не src/util.ts: util.ts делает относительный импорт "./consent.js"
  // (требование NodeNext-резолва) — без `npm run build` .js рядом нет, и
  // прямой импорт TS-исходника упал бы с ERR_MODULE_NOT_FOUND. `npm test`
  // всегда гоняет `npm run build` первым шагом (см. package.json), так что
  // dist/util.js к этому моменту уже свежий — тот же приём, что и в
  // test-no-agent-directives.mjs.
  const { okVerbatim, PRESENTATION_META_KEY } = await import("../dist/util.js");
  const wrapped = okVerbatim("тестовый отчёт", "execution-report");
  check("_meta содержит ключ PRESENTATION_META_KEY (ru.donskikh.mcp/presentation)", !!wrapped._meta?.[PRESENTATION_META_KEY], JSON.stringify(wrapped._meta));
  check("kind=execution-report", wrapped._meta?.[PRESENTATION_META_KEY]?.kind === "execution-report", wrapped._meta?.[PRESENTATION_META_KEY]?.kind);
  check("verbatim=true (не пересказывать)", wrapped._meta?.[PRESENTATION_META_KEY]?.verbatim === true);

  const files = readdirSync(new URL("../src/", import.meta.url), { recursive: true })
    .filter((f) => typeof f === "string" && f.endsWith(".ts"))
    .map((f) => "src/" + f);
  let rawMeta = 0;
  for (const f of files) {
    if (f === "src/util.ts") continue;
    const src = readFileSync(new URL("../" + f, import.meta.url), "utf8");
    // `_meta:` собранный вручную мимо okVerbatim/util.ts — потенциальный
    // второй неймспейс, который тест [7] иначе не поймает.
    if (/_meta\s*:/.test(src) && !/PRESENTATION_META_KEY/.test(src)) rawMeta++;
  }
  check("нигде в src/ нет ручной сборки _meta мимо PRESENTATION_META_KEY", rawMeta === 0, rawMeta);
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
