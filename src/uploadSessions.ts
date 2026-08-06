/**
 * uploadSessions.ts — серверная память об адресах возобновляемых загрузок.
 *
 * ЗАЧЕМ. Адрес сессии загрузки (resumable session URI) выдаёт САМ Google, в
 * ответ на запрос ЭТОГО сервера. Раньше сервер отдавал адрес наружу и потом
 * принимал его ОБРАТНО аргументом `gmail_confirm_upload` — то есть ходил по
 * адресу, пришедшему от модели, и возвращал тело ответа в диалог. Это
 * классическая подделка запроса со стороны сервера (SSRF): достаточно
 * уговорить модель подставить туда `http://169.254.169.254/…`, и сервер сам
 * сходит во внутреннюю сеть и вернёт ответ наружу.
 *
 * Лечение — не принимать адрес вообще: раз адрес выдал сервер, он может и
 * запомнить его у себя, а наружу отдать только непрозрачный `sessionId`.
 * Модель оперирует идентификатором, реальный адрес живёт на сервере и никогда
 * не приходит снаружи. (Клиенту адрес всё равно нужен — он льёт байты в
 * Google напрямую, — но обратно в инструмент он больше не возвращается.)
 *
 * Хранение — ровно как у `downloads.ts`: Postgres, когда он настроен, иначе
 * память процесса. Сессия Drive живёт около недели, дольше хранить нечего.
 */
import { randomBytes } from "node:crypto";
import { storeReady, saveUploadSession, getUploadSession, type UploadSessionRecord } from "./store.js";

export type { UploadSessionRecord };

/** Сессия возобновляемой загрузки у Google живёт ~неделю. */
export const UPLOAD_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const memory = new Map<string, UploadSessionRecord>();

/**
 * Запоминает адрес сессии и возвращает непрозрачный идентификатор, который
 * можно безопасно отдать модели.
 */
export async function rememberUploadSession(
  rec: Omit<UploadSessionRecord, "expiresAt">,
  ttlMs = UPLOAD_SESSION_TTL_MS,
): Promise<{ sessionId: string; expiresAt: number }> {
  const sessionId = randomBytes(24).toString("base64url");
  const record: UploadSessionRecord = { ...rec, expiresAt: Date.now() + ttlMs };
  if (storeReady()) {
    await saveUploadSession(sessionId, record);
  } else {
    for (const [k, v] of memory) if (v.expiresAt < Date.now()) memory.delete(k);
    memory.set(sessionId, record);
  }
  return { sessionId, expiresAt: record.expiresAt };
}

/** Адрес сессии по идентификатору; null — если такой сессии нет или истекла. */
export async function resolveUploadSession(sessionId: string): Promise<UploadSessionRecord | null> {
  if (storeReady()) return getUploadSession(sessionId);
  const rec = memory.get(sessionId);
  if (!rec) return null;
  if (rec.expiresAt < Date.now()) {
    memory.delete(sessionId);
    return null;
  }
  return rec;
}

/** Только для тестов: очищает память процесса между сценариями. */
export function _resetUploadSessionMemory(): void {
  memory.clear();
}
