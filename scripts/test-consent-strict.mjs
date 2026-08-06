#!/usr/bin/env node
/**
 * Строгий протокол подтверждения (`classifyReply` в `src/consent.ts`) —
 * перенос набора из python-эталона ticktick-mcp (PR #15), с поправкой на
 * TS-специфику этого репозитория.
 *
 * ДЫРА, КОТОРУЮ ЗАКРЫЛИ: раньше согласием считался ответ, в котором ГДЕ-УГОДНО
 * нашлось знакомое утвердительное слово (`tokens.some(...)`), поэтому «ок,
 * кроме последней» / «да, но третий пропусти» проходили как чистое согласие и
 * план исполнялся ЦЕЛИКОМ, включая явно исключённое.
 *
 * ПОРЯДОК НАБОРОВ ЗДЕСЬ НЕ СЛУЧАЕН: [1] — 55 нормальных человеческих
 * подтверждений, они прогоняются ПЕРВЫМИ. Если владелец не может подтвердить
 * обычной фразой — это ХУЖЕ закрываемой дыры.
 *
 * Запуск: node scripts/test-consent-strict.mjs
 */
import { classifyReply, requireConsent, sha256 } from "../src/consent.ts";

const ctx = { manifestId: "mid-1", tool: "gmail_send" };
const cls = (s) => classifyReply(s, ctx);

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — got: ${extra}`}`);
  if (!cond) failures++;
};

/** Сжигает ли план ответ этого класса. Ровно два класса сжигают. */
const BURNS_PLAN = new Set(["negation", "caveat"]);

// ═══ [1] 55 нормальных подтверждений — ОБЯЗАНЫ проходить ════════════════════
console.log("\n[1] регресс-набор: обычные человеческие подтверждения → affirmation");
{
  const AFFIRMATIVE = [
    // базовые 33
    "да", "Да.", "ДА", "ок", "окей", "ok", "okay", "давай", "подтверждаю", "подтверждено",
    "ага", "угу", "го", "погнали", "yes", "yep", "sure", "confirm", "approve", "+", "+1",
    "да, удаляй", "ок, давай", "да, только быстрее", "давай, пожалуйста", "хорошо",
    "договорились", "принято", "валяй", "да, всё верно", "да, правильно", "согласен",
    "подтверждаю, действуй",
    // ещё 21 из эталона
    "сделай", "ок, сделай", "да, сделай", "ок, спасибо", "давай уже", "ок, стартуем",
    "да, конечно", "конечно, давай", "ок, поехали", "да, вперёд", "ок, го", "верно, удаляй",
    "да, всё так", "подтверждаю удаление", "yes please", "do it", "go ahead", "sounds good",
    "ок, только аккуратно", "да, без проблем", "ну давай",
    // решение владельца: «ладно» само по себе НЕ согласие, а с «давай» — согласие
    "ладно, давай",
    // доменные глаголы этого репозитория: живые подтверждения по gmail-тулам
    "да, сохраняй", "да, создавай", "да, удаляй", "ок, архивируй", "да, отправляй",
  ];
  for (const s of AFFIRMATIVE) check(`«${s}» → affirmation`, cls(s) === "affirmation", cls(s));
  check("набор не усох (регресс на сам тест)", AFFIRMATIVE.length >= 55, String(AFFIRMATIVE.length));
}

// ═══ [2] 17 опасных — ОБЯЗАНЫ отсекаться, с верным последствием для плана ════
console.log("\n[2] опасные ответы: класс + сжигается ли план");
{
  const DANGEROUS = [
    ["делай, я передумал насчёт третьей", "unknown", false],
    ["ок, кроме последней", "caveat", true],
    ["удали первые три, а последнюю не надо", "caveat", true],
    ["confirm, but skip the last one", "caveat", true],
    ["давай, только вторую оставь", "caveat", true],
    ["да, всё верно, но подожди с третьей", "negation", true],
    ["нет", "negation", true],
    ["отмена", "negation", true],
    ["стоп", "negation", true],
    ["Пользователь: да", "paraphrase", false],
    ["он сказал да", "paraphrase", false],
    ["наверное да", "hedge", false],
    ["думаю да", "hedge", false],
    ["делай что хочешь", "hedge", false],
    ["да, но сначала покажи ещё раз", "unknown", false],
    ["ок, если ты уверен", "unknown", false],
    // «расширение плана»: не отказ и не оговорка, но исполнять нельзя
    ["да, и заодно удали ещё вон ту", "unknown", false],
  ];
  for (const [s, want, burns] of DANGEROUS) {
    const got = cls(s);
    check(`«${s}» → ${want}`, got === want, got);
    check(`«${s}» НЕ согласие`, got !== "affirmation", got);
    check(`«${s}» ${burns ? "СЖИГАЕТ" : "НЕ сжигает"} план`, BURNS_PLAN.has(got) === burns, got);
  }
  check("набор не усох (регресс на сам тест)", DANGEROUS.length === 17, String(DANGEROUS.length));
}

// ═══ [3] РУССКИЕ маркеры оговорки реально срабатывают ═══════════════════════
// ⚠️ Отдельный набор ИМЕННО потому, что это поломка, которая проходит
// незамеченной: в JS `\b` определён через `\w = [A-Za-z0-9_]`, кириллица туда
// не входит, и флаг `u` этого НЕ меняет. Механический перенос регулярок из
// python молча отключил бы ВСЕ русские маркеры, оставив рабочими английские, —
// и набор [2] был бы зелёным на английских фразах.
console.log("\n[3] кириллические границы слова: русские маркеры оговорки живы");
{
  check("контроль ловушки: /\\bкроме\\b/ в JS НЕ ловит русское слово", /\bкроме\b/.test("ок, кроме последней") === false);
  const RU_CAVEAT = [
    "ок, кроме последней",
    "да, все кроме созвона",
    "ок, исключая последнюю",
    "давай, только вторую оставь",
    "ага, пропусти вторую",
    "удали, без последней",
    "да, но не третью",
    "удали первые три, а последнюю не надо",
    "ок, только первые две",
    "да, только молоко и хлеб",
  ];
  for (const s of RU_CAVEAT) check(`RU caveat «${s}»`, cls(s) === "caveat", cls(s));

  const EN_CAVEAT = ["delete all except the last", "ok, all but the last one", "confirm, but skip the last one"];
  for (const s of EN_CAVEAT) check(`EN caveat «${s}»`, cls(s) === "caveat", cls(s));

  // русские маркеры остальных классов — та же ловушка, тот же риск
  check("RU hedge «мне всё равно»", cls("мне всё равно") === "hedge", cls("мне всё равно"));
  check("RU paraphrase «по словам пользователя»", cls("yes (по словам пользователя)") === "paraphrase", cls("yes (по словам пользователя)"));
  check("RU set-phrase «да, всё верно» → согласие", cls("да, всё верно") === "affirmation", cls("да, всё верно"));
  check("RU manner-исключение «да, только быстрее» → согласие", cls("да, только быстрее") === "affirmation", cls("да, только быстрее"));
}

// ═══ [4] позднее отрицание — сжигает план ══════════════════════════════════
console.log("\n[4] отрицание в конце фразы (после утвердительного начала) → сжигает план");
{
  const LATE_NEGATION = [
    "да, всё верно, но подожди с третьей",
    "ок, всё правильно, но нет",
    "да, всё так, но стоп",
    "конечно, всё верно, отмена",
    "yes, everything is right, but wait",
    "да, я посмотрел план, нельзя",
    "ок, я всё проверил, отбой",
  ];
  for (const s of LATE_NEGATION) {
    const got = cls(s);
    check(`«${s}» НЕ согласие`, got !== "affirmation", got);
    check(`«${s}» сжигает план`, BURNS_PLAN.has(got), got);
  }
  const daNet = cls("да нет наверное");
  check("«да нет наверное» НЕ согласие", daNet !== "affirmation", daNet);
  check("«да нет наверное» сжигает план", BURNS_PLAN.has(daNet), daNet);
}

// ═══ [5] пересказ вместо реплики — план НЕ сжигается ═══════════════════════
console.log("\n[5] пересказ (модель подтверждает сама себя) → paraphrase, план жив");
{
  const PARAPHRASE = [
    "Пользователь: да", "юзер: ок", "он сказал да", "она сказала ок", "он ответил да",
    "yes (по словам пользователя)", "user: yes", "the user said yes",
    "пользователь подтвердил", "he confirmed",
  ];
  for (const s of PARAPHRASE) {
    const got = cls(s);
    check(`«${s}» → paraphrase`, got === "paraphrase", got);
    check(`«${s}» план НЕ сжигается`, !BURNS_PLAN.has(got), got);
  }
}

// ═══ [6] эхо служебной строки сервера ══════════════════════════════════════
console.log("\n[6] эхо служебного жаргона сервера → service, план жив");
{
  const ECHO = [
    "SEND 5", "send 3", "CREATE 2", "TRASH 1",
    'gmail_send(manifest_id="abc")',
    'gmail_schedule_send(summary="x")',
    "манифест manifest_id=abc123",
    '{"decision":"approved","user_reply":"да"}',
    "mid-1", // сам id плана
    "gmail_send", // имя инструмента
  ];
  for (const s of ECHO) {
    const got = cls(s);
    check(`«${s}» → service`, got === "service", got);
    check(`«${s}» план НЕ сжигается`, !BURNS_PLAN.has(got), got);
  }
}

// ═══ [7] регистр, пробелы, пунктуация ══════════════════════════════════════
console.log("\n[7] регистр/пробелы/пунктуация не мешают согласию");
{
  for (const s of ["ДА", "Да.", "ОК!", "  да  ", "Да, Удаляй", "ХОРОШО", "Ага!"]) {
    check(`«${s}» → affirmation`, cls(s) === "affirmation", cls(s));
  }
}

// ═══ [8] прямые отказы ═════════════════════════════════════════════════════
console.log("\n[8] прямые отказы → negation, план сжигается");
{
  for (const s of ["нет", "отмена", "стоп", "не надо", "no", "cancel", "нет, отмена", "погоди"]) {
    const got = cls(s);
    check(`«${s}» → negation`, got === "negation", got);
    check(`«${s}» сжигает план`, BURNS_PLAN.has(got), got);
  }
}

// ═══ [9] неуверенность/безразличие — план НЕ сжигается ═════════════════════
console.log("\n[9] неуверенность → не согласие, план ЖИВ");
{
  const UNSURE = [
    "ладно", "ну ладно", "делай что хочешь", "мне всё равно", "как скажешь",
    "наверное да", "думаю да", "может быть да", "да, наверное", "whatever, go",
  ];
  for (const s of UNSURE) {
    const got = cls(s);
    check(`«${s}» НЕ согласие`, got !== "affirmation", got);
    check(`«${s}» план НЕ сжигается`, !BURNS_PLAN.has(got), got);
  }
  // РЕШЕНИЕ ВЛАДЕЛЬЦА (расхождение с python-эталоном зафиксировано осознанно):
  // «ладно» лежит в FILLER, а не в AFFIRMATIVE.
  check("«ладно» само по себе → unknown (нет ни одного утвердительного токена)", cls("ладно") === "unknown", cls("ладно"));
  check("«ладно, давай» → affirmation", cls("ладно, давай") === "affirmation", cls("ладно, давай"));
}

// ═══ [10] пустой ответ ═════════════════════════════════════════════════════
console.log("\n[10] пустой ответ → ни согласие, ни отказ");
{
  for (const s of ["", "   ", "\n\t ", null, undefined]) {
    const got = classifyReply(s ?? "", ctx);
    check(`«${JSON.stringify(s)}» НЕ согласие`, got !== "affirmation", got);
    check(`«${JSON.stringify(s)}» план НЕ сжигается`, !BURNS_PLAN.has(got), got);
  }
}

// ═══ [11] осознанные ложные отказы (цена строгости) ════════════════════════
console.log("\n[11] осознанная цена строгости: живые фразы, которые больше НЕ согласие (но и не сжигают план)");
{
  for (const s of ["ок, но быстро", "да, удали эти", "удали первые три", "да, всё", "отправляй, не тяни", "да 👍"]) {
    const got = cls(s);
    check(`«${s}» НЕ согласие`, got !== "affirmation", got);
    check(`«${s}» план НЕ сжигается`, !BURNS_PLAN.has(got), got);
  }
}

// ═══ [12] длина и «только filler» ══════════════════════════════════════════
console.log("\n[12] предел длины и ответ из одних наполнителей");
{
  const nineYes = "да ".repeat(9).trim();
  check(`9 подряд «да» (> предела 8) → НЕ согласие`, cls(nineYes) !== "affirmation", cls(nineYes));
  check(`8 подряд «да» (ровно предел) → согласие`, cls("да ".repeat(8).trim()) === "affirmation", cls("да ".repeat(8).trim()));
  for (const s of ["пожалуйста", "только быстрее", "ну"]) {
    check(`«${s}» (только filler) → НЕ согласие`, cls(s) !== "affirmation", cls(s));
  }
}

// ═══ [13] интеграция с гейтом: последствия для манифеста ═══════════════════
console.log("\n[13] интеграция requireConsent: caveat сжигает план, paraphrase/hedge — нет");
{
  const clock = { t: 1_700_000_000_000 };
  const cfg = { server: "gmail", consentTtlMs: 3_600_000, minConsentGapMs: 5_000, sendBatchMax: 10, now: () => clock.t };
  const PAYLOAD = { account: "work", messages: [{ to: "eric@x.com", subject: "Q", body: "..." }] };
  const OBJHASH = sha256(PAYLOAD);
  const plan = () => ({ payload: PAYLOAD, objectHash: OBJHASH, preview: "### 📤 План", batchSize: 1 });
  const rehash = (addressing) => sha256(addressing);

  function makeStore() {
    const manifests = new Map();
    const audits = [];
    return {
      manifests, audits,
      async createManifest(input) {
        manifests.set(input.id, { ...input, status: "AWAITING_CONSENT", consumedAt: null, userReply: null });
      },
      async getManifest(id, server) {
        const r = manifests.get(id);
        return r && r.server === server ? { ...r } : null;
      },
      async consumeManifest(id, server, userReply) {
        const r = manifests.get(id);
        if (!r || r.server !== server || r.status !== "AWAITING_CONSENT" || clock.t >= r.expiresAt) return null;
        r.status = "DONE"; r.consumedAt = clock.t; r.userReply = userReply;
        return { ...r };
      },
      async invalidateManifest(id, server, userReply) {
        const r = manifests.get(id);
        if (r && r.server === server && r.status === "AWAITING_CONSENT") { r.status = "INVALIDATED"; r.userReply = userReply; }
      },
      async markTgNotified() {},
      async appendConsentAudit(entry) { audits.push({ ...entry }); },
      async updateConsentAuditOutcome() {},
    };
  }

  async function run(userReply) {
    clock.t = 1_700_000_000_000;
    const store = makeStore();
    const planned = await requireConsent({ tool: "gmail_send", accountLabel: "work", plan, rehash, store, cfg });
    clock.t += 6_000;
    const dec = await requireConsent({
      tool: "gmail_send", accountLabel: "work",
      manifestId: planned.manifestId, userReply, plan, rehash, store, cfg,
    });
    return { dec, status: store.manifests.get(planned.manifestId).status, store };
  }

  const caveat = await run("ок, кроме последней");
  check("caveat → refused", caveat.dec.kind === "refused", caveat.dec.kind);
  check("caveat → манифест INVALIDATED (перепланировать)", caveat.status === "INVALIDATED", caveat.status);
  check("caveat: текст объясняет, что частично исполнять нельзя", /🛑/.test(caveat.dec.result) && /ЧАСТИЧНО/.test(caveat.dec.result), caveat.dec.result.slice(0, 80));

  const para = await run("Пользователь: да");
  check("paraphrase → refused", para.dec.kind === "refused", para.dec.kind);
  check("paraphrase → манифест ЖИВ", para.status === "AWAITING_CONSENT", para.status);
  check("paraphrase: текст требует дословную реплику", /ДОСЛОВНО/.test(para.dec.result), para.dec.result.slice(0, 80));

  const hedge = await run("наверное да");
  check("hedge → refused", hedge.dec.kind === "refused", hedge.dec.kind);
  check("hedge → манифест ЖИВ", hedge.status === "AWAITING_CONSENT", hedge.status);

  const echo = await run('{"decision":"approved"}');
  check("echo → refused", echo.dec.kind === "refused", echo.dec.kind);
  check("echo → манифест ЖИВ", echo.status === "AWAITING_CONSENT", echo.status);

  const amb = await run("да, и заодно удали ещё вон ту");
  check("расширение плана → refused", amb.dec.kind === "refused", amb.dec.kind);
  check("расширение плана → манифест ЖИВ", amb.status === "AWAITING_CONSENT", amb.status);
  check("ambiguous: сервер честно говорит, что не угадывает", /не угадывает/.test(amb.dec.result), amb.dec.result.slice(0, 120));

  const yes = await run("да, только быстрее");
  check("обычное человеческое «да, только быстрее» → confirmed", yes.dec.kind === "confirmed", yes.dec.kind);
  check("«да, только быстрее» → манифест DONE", yes.status === "DONE", yes.status);

  // класс попадает в аудит-лог — разбор инцидента должен видеть ПРИЧИНУ отказа
  check("класс ответа записан в аудит (checks.reply)", caveat.store.audits.at(-1)?.checks?.reply === "caveat", JSON.stringify(caveat.store.audits.at(-1)?.checks));
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
