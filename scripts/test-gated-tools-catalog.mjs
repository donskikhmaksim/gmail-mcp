#!/usr/bin/env node
/**
 * gated_tools_catalog.ts — автосправочник гейтированных методов
 * (docs/TZ_automation_key_method_catalog.md раздел 1, тестовый план п.1).
 *
 * A) `listGatedTools` против СИНТЕТИЧЕСКОГО тестового McpServer с одним
 *    гейтированным (несёт `automation_key` в inputSchema) и одним НЕ
 *    гейтированным тулом — в списке оказывается ТОЛЬКО гейтированный.
 * B) `buildGatedToolsCatalog()` против РЕАЛЬНОГО gmail-mcp сервера
 *    (buildMcpServer через синтетического catalog-пользователя) — сверяем
 *    список имён с известным списком `tool: "..."` в src/tools/gmail.ts
 *    (тот же список, что и requireConsent-вызовы этого репо).
 *
 * Usage: node scripts/test-gated-tools-catalog.mjs (после `npm run build` —
 * этот файл, в отличие от `consent.ts`/`automation_key.ts`, реально ИМПОРТИРУЕТ
 * `server.ts` (для `buildMcpServer`), у которого есть собственное дерево
 * относительных импортов — то же ограничение, что у `test-automation-key-gate.mjs`,
 * которое поэтому грузит `../dist/tools/gmail.js`, а не `../src/tools/gmail.ts`
 * напрямую: raw type-stripping в Node НЕ резолвит `./server.js` → `./server.ts`
 * через цепочку модулей, только билд это разруливает через tsc).
 */
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { listGatedTools, buildGatedToolsCatalog } from "../dist/gated_tools_catalog.js";

let failures = 0;
const check = (label, cond, extra = "") => {
  console.log(`${cond ? "  ok  " : "  FAIL"} ${label}${cond ? "" : ` — ${extra}`}`);
  if (!cond) failures++;
};

// ═══════════════════════ A) синтетический сервер ═══════════════════════════

console.log("\n[A] listGatedTools фильтрует ТОЛЬКО тулы с automation_key в схеме");
{
  const server = new McpServer({ name: "catalog-test", version: "0" });
  server.registerTool(
    "gated_demo_tool",
    {
      description: "Demo gated tool for the catalog test — mutates something.",
      inputSchema: {
        thing: z.string(),
        automation_key: z.string().optional().describe("headless automation key"),
      },
    },
    async () => ({ content: [{ type: "text", text: "ok" }] }),
  );
  server.registerTool(
    "readonly_demo_tool",
    {
      description: "Demo read-only tool WITHOUT automation_key — must not appear in the catalog.",
      inputSchema: { query: z.string().optional() },
      annotations: { readOnlyHint: true },
    },
    async () => ({ content: [{ type: "text", text: "ok" }] }),
  );

  const gated = await listGatedTools(server);
  check("ровно один тул в каталоге", gated.length === 1, String(gated.length));
  check("это gated_demo_tool", gated[0]?.name === "gated_demo_tool", JSON.stringify(gated));
  check("readonly_demo_tool НЕ попал в каталог", !gated.some((t) => t.name === "readonly_demo_tool"));
  check("description непустое", typeof gated[0]?.description === "string" && gated[0].description.length > 0);
}

// ═══════════════════════ B) реальный gmail-mcp каталог ═════════════════════

console.log("\n[B] buildGatedToolsCatalog() против реального сервера — совпадает с известным списком");
{
  // Тот же список, что requireConsent-вызовы в src/tools/gmail.ts (`tool: "..."`)
  // — намеренно захардкожен здесь как независимая проверка (регресс: если кто-то
  // забудет automation_key на новом гейтированном тулах, этот тест не поймает
  // РАСХОЖДЕНИЕ само по себе — но он ловит, что каталог реально видит все
  // ИЗВЕСТНЫЕ на сегодня 17).
  const EXPECTED = [
    "gmail_archive",
    "gmail_cancel_scheduled_send",
    "gmail_create_draft",
    "gmail_create_label",
    "gmail_create_upload_session",
    "gmail_delete_label",
    "gmail_export_thread_eml",
    "gmail_forward",
    "gmail_get_download_url",
    "gmail_modify_labels",
    "gmail_reply",
    "gmail_save_attachment_to_drive",
    "gmail_schedule_send",
    "gmail_send",
    "gmail_snooze",
    "gmail_trash",
    "gmail_update_label",
  ].sort();

  const catalog = await buildGatedToolsCatalog();
  const names = catalog.map((t) => t.name).sort();

  check("каталог содержит ровно 17 гейтированных тулов", names.length === EXPECTED.length, String(names.length));
  check("имена совпадают с известным списком", JSON.stringify(names) === JSON.stringify(EXPECTED), JSON.stringify(names));
  check(
    "ни один ungated read-инструмент (например list_accounts) не просочился",
    !names.includes("list_accounts"),
  );
  check(
    "каждый элемент несёт непустые name и description",
    catalog.every((t) => typeof t.name === "string" && t.name.length > 0 && typeof t.description === "string"),
  );
}

console.log(`\n${failures === 0 ? "ALL CHECKS PASSED" : `${failures} CHECK(S) FAILED`}`);
process.exit(failures === 0 ? 0 : 1);
