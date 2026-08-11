#!/usr/bin/env node
/**
 * Offline unit-тест `src/note_crypto.ts` — портируемой byte-for-byte копии
 * `self-destroyed-notes`'s `crypto.ts` (`generateKey()`/`encrypt()`).
 * Spec: `docs/TZ_automation_key_note_delivery_and_buttons.md`, тестовый
 * план п.3: "encrypt/generateKey дают payload, который РЕАЛЬНО
 * расшифровывается обратно тем же алгоритмом" — не полагаться на то, что
 * "выглядит похоже на оригинал", а фактически проверить дешифровку.
 *
 * Дешифровка (`decryptForTest` ниже) НЕ экспортируется из `note_crypto.ts`
 * — gmail-mcp никогда не расшифровывает заметки в проде (это делает
 * браузер получателя, WebCrypto), только шифрует. Здесь она реализована
 * заново по тому же алгоритму (обратная операция `encrypt`) исключительно
 * для проверки round-trip.
 *
 * Запуск: node scripts/test-note-crypto.mjs
 */
import crypto from "node:crypto";
import { generateKey, encrypt } from "../src/note_crypto.ts";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

/** Обратная операция `encrypt()` — AES-256-GCM с ключом, выведенным той же
 * PBKDF2-SHA256(salt, iter), что и сам модуль. Независимая реализация здесь
 * НЕ была бы бессмысленной копией: `encrypt()` намеренно не экспортирует
 * decrypt (gmail-mcp его не использует в проде) — это ЭТАЛОННАЯ проверка
 * того, что зашифрованный payload реально обратим тем же алгоритмом. */
function decryptForTest(payload, keyB64Url, password) {
  const urlKey = Buffer.from(keyB64Url, "base64url");
  const kdfInput = payload.pw ? Buffer.concat([urlKey, Buffer.from(password ?? "", "utf8")]) : urlKey;
  const salt = Buffer.from(payload.salt, "base64");
  const key = crypto.pbkdf2Sync(kdfInput, salt, payload.iter, 32, "sha256");
  const iv = Buffer.from(payload.iv, "base64");
  const dataAndTag = Buffer.from(payload.data, "base64");
  const tag = dataAndTag.subarray(dataAndTag.length - 16);
  const encrypted = dataAndTag.subarray(0, dataAndTag.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

console.log("\n[1] generateKey() — 32 случайных байта, base64url, не пусто/предсказуемо");
{
  const k1 = generateKey();
  const k2 = generateKey();
  check("ключ — непустая строка", typeof k1 === "string" && k1.length > 0, k1);
  check("два вызова дают РАЗНЫЕ ключи (не константа)", k1 !== k2);
  check("декодируется base64url ровно в 32 байта", Buffer.from(k1, "base64url").length === 32, Buffer.from(k1, "base64url").length);
  check("не содержит стандартных base64-символов +/= (это base64url)", !/[+/=]/.test(k1), k1);
}

console.log("\n[2] encrypt() → payload корректной формы (v1, pw=false без пароля)");
{
  const key = generateKey();
  const plaintext = "тестовый automation_key raw-токен 🔑 с юникодом и эмодзи";
  const payload = encrypt(plaintext, key);
  check("v === 1", payload.v === 1, payload.v);
  check("pw === false (пароль не передан)", payload.pw === false, payload.pw);
  check("iter === 100000", payload.iter === 100_000, payload.iter);
  check("iv/data/salt — непустые base64-строки", [payload.iv, payload.data, payload.salt].every((s) => typeof s === "string" && s.length > 0));
  check("iv декодируется в 12 байт (GCM nonce)", Buffer.from(payload.iv, "base64").length === 12, Buffer.from(payload.iv, "base64").length);
  check("salt декодируется в 16 байт", Buffer.from(payload.salt, "base64").length === 16, Buffer.from(payload.salt, "base64").length);
  check("payload.data НЕ содержит plaintext буквально (реально зашифровано)", !Buffer.from(payload.data, "base64").toString("utf8").includes(plaintext));
}

console.log("\n[3] round-trip: encrypt → decrypt (тем же алгоритмом, вручную в тесте) даёт исходный plaintext (тестовый план п.3)");
{
  const cases = [
    "простой ASCII automation_key raw token",
    "с юникодом: рабочий ноутбук 🔑✅",
    "",
    "a".repeat(5000), // длинный текст — проверяет, что chunked cipher.update/final склеены верно
  ];
  for (const plaintext of cases) {
    const key = generateKey();
    const payload = encrypt(plaintext, key);
    const decrypted = decryptForTest(payload, key);
    check(`round-trip корректен для: "${plaintext.slice(0, 30)}${plaintext.length > 30 ? "..." : ""}" (len=${plaintext.length})`, decrypted === plaintext, { decrypted, plaintext });
  }
}

console.log("\n[4] round-trip с паролем (pw=true) — decrypt с ПРАВИЛЬНЫМ паролем проходит, с НЕВЕРНЫМ — падает (auth tag не сходится)");
{
  const key = generateKey();
  const plaintext = "секрет с дополнительным паролем";
  const password = "correct-horse-battery-staple";
  const payload = encrypt(plaintext, key, password);
  check("pw === true", payload.pw === true, payload.pw);

  const decrypted = decryptForTest(payload, key, password);
  check("decrypt с правильным паролем даёт исходный plaintext", decrypted === plaintext, decrypted);

  let threw = false;
  try {
    decryptForTest(payload, key, "wrong-password");
  } catch {
    threw = true;
  }
  check("decrypt с НЕВЕРНЫМ паролем бросает исключение (GCM auth tag не совпал, не тихо портит данные)", threw);
}

console.log("\n[5] неверный ключ (32 случайных байта, но не тот, что шифровал) → decrypt падает, а не тихо даёт мусор");
{
  const key = generateKey();
  const wrongKey = generateKey();
  const payload = encrypt("любой plaintext", key);
  let threw = false;
  try {
    decryptForTest(payload, wrongKey);
  } catch {
    threw = true;
  }
  check("decrypt с чужим ключом бросает исключение (auth tag mismatch)", threw);
}

console.log("\n[6] encrypt() с ключом неправильной длины — бросает исключение (fail-closed, не тихо укорачивает/дополняет)");
{
  let threw = false;
  try {
    encrypt("plaintext", Buffer.from("слишком короткий ключ").toString("base64url"));
  } catch {
    threw = true;
  }
  check("encrypt с ключом неправильной длины бросает исключение", threw);
}

console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL CHECKS PASSED");
process.exit(failures ? 1 : 0);
