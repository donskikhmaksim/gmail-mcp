/**
 * Google Docs tools.
 */
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { docs_v1 } from "googleapis";
import { ok, guard } from "../util.js";
import { accountField, type UserClients } from "../accounts.js";

/** Flattens a Docs document body into plain text. */
export function documentToPlainText(doc: docs_v1.Schema$Document): string {
  const out: string[] = [];
  const content = doc.body?.content ?? [];
  for (const el of content) {
    const para = el.paragraph;
    if (para?.elements) {
      for (const pe of para.elements) {
        const t = pe.textRun?.content;
        if (t) out.push(t);
      }
    }
    const table = el.table;
    if (table?.tableRows) {
      for (const row of table.tableRows) {
        const cells = (row.tableCells ?? []).map((cell) => {
          const parts: string[] = [];
          for (const cc of cell.content ?? []) {
            for (const pe of cc.paragraph?.elements ?? []) {
              if (pe.textRun?.content) parts.push(pe.textRun.content.trim());
            }
          }
          return parts.join(" ");
        });
        out.push(cells.join("\t") + "\n");
      }
    }
  }
  return out.join("");
}

/** Returns the end index of the document body (where appended text should go). */
function documentEndIndex(doc: docs_v1.Schema$Document): number {
  const content = doc.body?.content ?? [];
  let end = 1;
  for (const el of content) {
    if (typeof el.endIndex === "number") end = el.endIndex;
  }
  // The very last newline of the body is not a valid insertion location;
  // insert just before it.
  return Math.max(1, end - 1);
}

export function registerDocsTools(server: McpServer, clients: UserClients) {
  const account = accountField(clients);

  server.registerTool(
    "docs_list",
    {
      title: "List documents",
      description:
        "List Google Docs the account can access. Optionally filter by a name substring.",
      inputSchema: {
        account,
        nameContains: z.string().optional(),
        maxResults: z.number().int().min(1).max(200).default(50).optional(),
      },
    },
    guard(async ({ account, nameContains, maxResults }) => {
      const g = clients.resolve(account);
      const qParts = [
        "mimeType='application/vnd.google-apps.document'",
        "trashed=false",
      ];
      if (nameContains) {
        qParts.push(`name contains '${nameContains.replace(/'/g, "\\'")}'`);
      }
      const res = await g.drive.files.list({
        q: qParts.join(" and "),
        pageSize: maxResults ?? 50,
        fields: "files(id,name,modifiedTime,webViewLink)",
        orderBy: "modifiedTime desc",
      });
      const files = res.data.files ?? [];
      return ok({
        summary: `📋 ${files.length} document(s)${nameContains ? ` matching "${nameContains}"` : ""} on account "${account ?? "default"}"`,
        files,
      });
    }),
  );

  server.registerTool(
    "docs_read",
    {
      title: "Read document",
      description:
        "Read a Google Doc as plain text. Set `raw` to true to get the full structural JSON instead.",
      inputSchema: {
        account,
        documentId: z.string(),
        raw: z.boolean().default(false).optional(),
      },
    },
    guard(async ({ account, documentId, raw }) => {
      const g = clients.resolve(account);
      const res = await g.docs.documents.get({ documentId });
      if (raw) return ok(res.data);
      const text = documentToPlainText(res.data);
      return ok({
        summary: `📖 Read "${res.data.title ?? documentId}" — ${text.length} char(s)`,
        title: res.data.title,
        documentId: res.data.documentId,
        text,
      });
    }),
  );

  server.registerTool(
    "docs_create",
    {
      title: "Create document",
      description:
        "Create a new Google Doc, optionally with initial text. Returns its id.",
      inputSchema: {
        account,
        title: z.string(),
        text: z.string().optional().describe("Optional initial body text."),
      },
    },
    guard(async ({ account, title, text }) => {
      const g = clients.resolve(account);
      const created = await g.docs.documents.create({ requestBody: { title } });
      const documentId = created.data.documentId!;
      if (text) {
        await g.docs.documents.batchUpdate({
          documentId,
          requestBody: {
            requests: [{ insertText: { location: { index: 1 }, text } }],
          },
        });
      }
      return ok({
        summary: `📄 Created document "${created.data.title ?? title}"`,
        documentId,
        title: created.data.title,
        url: `https://docs.google.com/document/d/${documentId}/edit`,
      });
    }),
  );

  server.registerTool(
    "docs_append_text",
    {
      title: "Append text",
      description: "Append text to the end of a document.",
      inputSchema: {
        account,
        documentId: z.string(),
        text: z.string(),
      },
    },
    guard(async ({ account, documentId, text }) => {
      const g = clients.resolve(account);
      const doc = await g.docs.documents.get({ documentId });
      const index = documentEndIndex(doc.data);
      const res = await g.docs.documents.batchUpdate({
        documentId,
        requestBody: { requests: [{ insertText: { location: { index }, text } }] },
      });
      return ok({
        summary: `📝 Appended ${text.length} char(s) to "${doc.data.title ?? documentId}"`,
        ok: true,
        writeControl: res.data.writeControl ?? null,
      });
    }),
  );

  server.registerTool(
    "docs_insert_text",
    {
      title: "Insert text at index",
      description:
        "Insert text at a specific character index (1 = very start of the body).",
      inputSchema: {
        account,
        documentId: z.string(),
        index: z.number().int().min(1),
        text: z.string(),
      },
    },
    guard(async ({ account, documentId, index, text }) => {
      const g = clients.resolve(account);
      let docTitle: string | null = null;
      try {
        const meta = await g.docs.documents.get({ documentId });
        docTitle = meta.data.title ?? null;
      } catch {}
      await g.docs.documents.batchUpdate({
        documentId,
        requestBody: { requests: [{ insertText: { location: { index }, text } }] },
      });
      return ok({
        summary: `📝 Inserted ${text.length} char(s) at index ${index} in "${docTitle ?? documentId}"`,
        ok: true,
      });
    }),
  );

  server.registerTool(
    "docs_replace_text",
    {
      title: "Replace all text",
      description: "Find and replace all occurrences of a string in a document.",
      inputSchema: {
        account,
        documentId: z.string(),
        find: z.string(),
        replace: z.string(),
        matchCase: z.boolean().default(false).optional(),
      },
    },
    guard(async ({ account, documentId, find, replace, matchCase }) => {
      const g = clients.resolve(account);
      let docTitle: string | null = null;
      try {
        const meta = await g.docs.documents.get({ documentId });
        docTitle = meta.data.title ?? null;
      } catch {}
      const res = await g.docs.documents.batchUpdate({
        documentId,
        requestBody: {
          requests: [
            {
              replaceAllText: {
                containsText: { text: find, matchCase: matchCase ?? false },
                replaceText: replace,
              },
            },
          ],
        },
      });
      const occurrencesChanged = res.data.replies?.[0]?.replaceAllText?.occurrencesChanged ?? 0;
      return ok({
        summary: `🔄 Replaced "${find}" → "${replace}" in "${docTitle ?? documentId}" — ${occurrencesChanged} occurrence(s)`,
        occurrencesChanged,
      });
    }),
  );

  server.registerTool(
    "docs_raw_batch_update",
    {
      title: "Raw Docs batchUpdate (advanced)",
      description:
        "Send raw Docs API batchUpdate `requests` (styling, tables, images, etc.). Use only when other tools are not enough.",
      inputSchema: {
        account,
        documentId: z.string(),
        requests: z.array(z.record(z.string(), z.any())),
      },
    },
    guard(async ({ account, documentId, requests }) => {
      const g = clients.resolve(account);
      const res = await g.docs.documents.batchUpdate({
        documentId,
        requestBody: { requests: requests as object[] },
      });
      return ok({
        summary: `⚙️ Applied ${requests.length} raw request(s) to document ${documentId}`,
        documentId: res.data.documentId,
        replies: res.data.replies,
        writeControl: res.data.writeControl,
      });
    }),
  );
}
