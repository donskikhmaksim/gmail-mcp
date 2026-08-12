/**
 * gated_tools_catalog.ts — автоматический справочник гейтированных методов
 * этого сервера. Spec: `docs/TZ_automation_key_method_catalog.md` разделы 1-2.
 *
 * ПОЧЕМУ InMemoryTransport + client.listTools(), а НЕ приватное поле
 * `_registeredTools` на `McpServer`: `_registeredTools` физически доступно
 * (JS не запрещает читать "приватные" поля TS-класса в рантайме), но это НЕ
 * публичный контракт SDK — может переименоваться/поменять форму на любом
 * апдейте `@modelcontextprotocol/sdk` без предупреждения в CHANGELOG (это не
 * часть протокола, только деталь реализации). `InMemoryTransport.
 * createLinkedPair()` — штатная утилита самого SDK (используется в его же
 * тестах, и уже используется в этом репозитории — см. `scripts/
 * test-a3-gate.mjs`, `scripts/test-automation-key-gate.mjs`,
 * `scripts/test-gate-coverage.mjs`): она гоняет НАСТОЯЩИЙ протокольный запрос
 * `tools/list` через связанную пару транспортов в памяти процесса (без
 * сети), так что список тулов приходит через ТОТ ЖЕ путь, каким его увидела
 * бы любая настоящая модель — включая JSON-схему параметров, из которой и
 * определяется «гейтирован ли тул».
 *
 * КРИТЕРИЙ «гейтирован» (ТЗ раздел 1): `inputSchema.properties.automation_key`
 * присутствует в JSON-схеме, отданной `tools/list`. Каждый гейтированный тул
 * УЖЕ ОБЯЗАН нести этот Zod-параметр (docs/TZ_automation_key_consent_gate.md)
 * — значит критерий точный и не требует отдельного ручного списка нигде.
 *
 * ЗАВИСИМОСТЬ ОТ user: список ИМЁН тулов и их гейтированность НЕ зависят от
 * конкретного пользователя/аккаунтов (см. `src/tools/gmail.ts`'s
 * `registerGmailTools` — набор `server.registerTool(...)` вызовов фиксирован
 * в коде, `clients`/`user` влияют только на ТЕКСТ описания аккаунтов внутри
 * некоторых `description`, не на состав тулов и не на их inputSchema). Поэтому
 * каталог строится на СИНТЕТИЧЕСКОМ пользователе (`CATALOG_USER` ниже) —
 * он никогда не используется для реальных вызовов, только чтобы пройти тот
 * же путь сборки сервера (`buildMcpServer`), которым идёт обычный запрос.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { User } from "./config.js";
import { buildMcpServer } from "./server.js";

export interface GatedToolInfo {
  name: string;
  description: string;
}

/** UI-разумный потолок длины описания (ТЗ раздел 1 п.4 — "если слишком
 * длинное для UI — можно обрезать разумно, отметь в отчёте"). Обрезаем по
 * кодовым точкам, не по UTF-16-единицам — та же дисциплина, что `inlineReply`
 * в `consent.ts` (не разрывать эмодзи пополам). */
const DESCRIPTION_MAX_LEN = 220;

function truncateDescription(s: string, max = DESCRIPTION_MAX_LEN): string {
  const one = s.replace(/\s+/g, " ").trim();
  if (one.length <= max) return one;
  let out = "";
  for (const ch of one) {
    if (out.length + ch.length > max) break;
    out += ch;
  }
  return out + "…";
}

/**
 * Синтетический пользователь ТОЛЬКО для построения каталога — никогда не
 * ходит в реальный Google API (тулы каталога не вызываются, только
 * перечисляются через `tools/list`; `createGoogleClients` строит клиент
 * лениво, без сетевого вызова при конструировании — см. `src/google.ts`).
 */
const CATALOG_USER: User = {
  name: "gated-tools-catalog",
  accounts: [
    {
      name: "catalog",
      auth: { mode: "oauth", clientId: "catalog", clientSecret: "catalog", refreshToken: "catalog" },
    },
  ],
  defaultAccount: "catalog",
};

/** Строит новый `McpServer` исключительно для перечисления тулов (см.
 * doc-comment модуля выше про синтетического пользователя). Отдельная
 * функция, а не переиспользование "боевого" сервера — вызывающий код
 * (`listGatedTools`) сам закрывает этот сервер после использования, что было
 * бы некорректно делать с сервером живого MCP-соединения. */
export function buildCatalogServer(): McpServer {
  return buildMcpServer(CATALOG_USER);
}

/**
 * Перечисляет все ГЕЙТИРОВАННЫЕ тулы уже собранного `server` через штатный
 * протокольный `tools/list` (см. doc-comment модуля выше). Открывает и
 * закрывает связанную пару транспортов + клиента сама — не течёт наружу.
 */
export async function listGatedTools(server: McpServer): Promise<GatedToolInfo[]> {
  const client = new Client({ name: "gated-tools-catalog", version: "1.0.0" });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();

  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  try {
    const res = await client.listTools();
    const gated: GatedToolInfo[] = [];
    for (const tool of res.tools) {
      const schema = tool.inputSchema as { properties?: Record<string, unknown> } | undefined;
      const hasAutomationKey =
        !!schema && !!schema.properties && Object.prototype.hasOwnProperty.call(schema.properties, "automation_key");
      if (!hasAutomationKey) continue;
      gated.push({ name: tool.name, description: truncateDescription(tool.description ?? "") });
    }
    return gated;
  } finally {
    // Оба конца — клиент и сервер — держат ресурсы связанной InMemory-пары;
    // закрываем оба, чтобы не течь (ТЗ раздел 1 п.5).
    await Promise.all([client.close(), server.close()]);
  }
}

/** Удобная обёртка: строит одноразовый каталожный сервер и сразу
 * перечисляет его гейтированные тулы. Используется HTTP-роутом
 * `GET /automation-key-catalog` (`http.ts`). */
export async function buildGatedToolsCatalog(): Promise<GatedToolInfo[]> {
  return listGatedTools(buildCatalogServer());
}
