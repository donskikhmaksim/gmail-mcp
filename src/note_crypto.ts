/**
 * note_crypto.ts — портируемая копия byte-for-byte шифрования из
 * `self-destroyed-notes` (`/Users/maksim/Code/self-destroyed-notes/src/crypto.ts`,
 * функции `generateKey()`/`encrypt()`). Spec:
 * `docs/TZ_automation_key_note_delivery_and_buttons.md` раздел 1.
 *
 * НЕ импортировать `self-destroyed-notes` как npm-зависимость — у gmail-mcp
 * нет доступа к этому репозиторию как к пакету (отдельный, несвязанный
 * репозиторий на диске владельца). Дублирование этих ~35 строк — тот же
 * приём, что уже применён для automation_key.ts/tg_approval.ts (см.
 * doc-comment в начале automation_key.ts про отсутствие runtime-импортов
 * между "сестринскими" модулями, тестируемыми напрямую через `node
 * scripts/test-*.mjs` без сборки).
 *
 * Сервер self-destroyed-notes НИКОГДА не видит ключ расшифровки —
 * шифрование делает вызывающая сторона (здесь — gmail-mcp), ключ живёт
 * только во фрагменте URL, который отдаётся владельцу.
 */
import crypto from "node:crypto";

// Encrypted payload as stored by the server. The server never stores the key —
// the key only ever exists in the URL fragment that the recipient receives.
//
// Key derivation matches the browser (WebCrypto) so any payload — created in the
// web UI, the Mini App, or the bot fallback — decrypts the same way:
//   AES-256-GCM key = PBKDF2-SHA256( urlKey [|| password], salt, iter )
export interface NotePayload {
  v: 1;
  iv: string; // base64
  data: string; // base64 (ciphertext || GCM auth tag), matches WebCrypto layout
  salt: string; // base64
  iter: number; // PBKDF2 iterations
  pw: boolean; // whether a password is also required to derive the key
}

const KEY_BYTES = 32; // AES-256
const IV_BYTES = 12; // GCM standard nonce
const SALT_BYTES = 16;
const ITERATIONS = 100_000;

/**
 * Generate a fresh random 256-bit key, base64url-encoded for embedding in a URL
 * fragment. Used by the Telegram bot fallback path (server-side encryption).
 */
export function generateKey(): string {
  return crypto.randomBytes(KEY_BYTES).toString("base64url");
}

/**
 * Encrypt plaintext using AES-256-GCM with a key derived from the URL key and an
 * optional password. Byte-compatible with the browser's WebCrypto, so the web
 * client can decrypt it directly.
 *
 * `password` намеренно не используется вызывающим кодом gmail-mcp в этом
 * заходе (ТЗ раздел "Явно НЕ входит" — password-защита заметки не
 * запрошена), но параметр оставлен ради точного byte-for-byte соответствия
 * оригиналу.
 */
export function encrypt(plaintext: string, keyB64Url: string, password?: string): NotePayload {
  const urlKey = Buffer.from(keyB64Url, "base64url");
  if (urlKey.length !== KEY_BYTES) throw new Error("invalid key length");

  const pw = !!password;
  const salt = crypto.randomBytes(SALT_BYTES);
  const kdfInput = pw ? Buffer.concat([urlKey, Buffer.from(password!, "utf8")]) : urlKey;
  const key = crypto.pbkdf2Sync(kdfInput, salt, ITERATIONS, KEY_BYTES, "sha256");

  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const data = Buffer.concat([enc, tag]);

  return {
    v: 1,
    iv: iv.toString("base64"),
    data: data.toString("base64"),
    salt: salt.toString("base64"),
    iter: ITERATIONS,
    pw,
  };
}
