/**
 * Renders the account-management dashboard — the "add your emails" UI.
 * Pure string builder (no template engine) so the core has zero extra deps.
 */
import type { GoogleAccountMeta } from "./store.js";

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string,
  );
}

const MESSAGES: Record<string, string> = {
  added: "Аккаунт добавлен.",
  removed: "Аккаунт удалён.",
  default: "Аккаунт по умолчанию обновлён.",
  renamed: "Метка изменена.",
  rename_failed: "Не удалось переименовать (такая метка уже занята?).",
};

export function renderDashboard(
  base: string,
  accounts: GoogleAccountMeta[],
  msg?: string,
): string {
  const banner = msg && MESSAGES[msg]
    ? `<div class="banner">${esc(MESSAGES[msg])}</div>`
    : "";

  const rows = accounts.length
    ? accounts
        .map((a) => {
          const badge = a.isDefault ? `<span class="badge">по умолчанию</span>` : "";
          const makeDefault = a.isDefault
            ? ""
            : `<form method="post" action="${base}/default" class="inline">
                 <input type="hidden" name="email" value="${esc(a.email)}">
                 <button class="link">сделать основным</button>
               </form>`;
          return `
          <div class="card">
            <div class="row">
              <div>
                <div class="email">${esc(a.email)} ${badge}</div>
                <form method="post" action="${base}/rename" class="rename">
                  <input type="hidden" name="email" value="${esc(a.email)}">
                  <input name="label" value="${esc(a.label)}" maxlength="40" spellcheck="false">
                  <button class="link">переименовать</button>
                  <span class="hint">метка для выбора в Claude (параметр account)</span>
                </form>
              </div>
              <div class="actions">
                ${makeDefault}
                <form method="post" action="${base}/remove" class="inline"
                      onsubmit="return confirm('Удалить ${esc(a.email)}? Claude потеряет доступ к этому аккаунту.')">
                  <input type="hidden" name="email" value="${esc(a.email)}">
                  <button class="link danger">удалить</button>
                </form>
              </div>
            </div>
          </div>`;
        })
        .join("")
    : `<div class="empty">Пока нет подключённых Google-аккаунтов. Нажми «Добавить аккаунт».</div>`;

  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Мои Google-аккаунты</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #f5f5f7; color: #1a1a1a; margin: 0; padding: 32px 16px; }
  .wrap { max-width: 640px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #666; font-size: 14px; margin: 0 0 24px; }
  .banner { background: #e7f6ec; color: #1a7a3d; border-radius: 10px;
            padding: 10px 14px; font-size: 14px; margin-bottom: 16px; }
  .card { background: #fff; border-radius: 12px; padding: 16px 18px;
          box-shadow: 0 1px 4px rgba(0,0,0,.06); margin-bottom: 12px; }
  .row { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
  .email { font-weight: 600; font-size: 15px; margin-bottom: 8px; word-break: break-all; }
  .badge { display: inline-block; background: #eef1ff; color: #3a49c8; font-size: 11px;
           font-weight: 600; padding: 2px 8px; border-radius: 999px; vertical-align: middle; }
  .rename { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .rename input { font-size: 13px; padding: 5px 8px; border: 1px solid #d5d5da;
                  border-radius: 7px; width: 140px; }
  .hint { color: #999; font-size: 11px; }
  .actions { display: flex; flex-direction: column; align-items: flex-end; gap: 8px; white-space: nowrap; }
  .inline { display: inline; }
  button.link { background: none; border: none; color: #3a49c8; cursor: pointer;
                font-size: 13px; padding: 0; }
  button.link:hover { text-decoration: underline; }
  button.link.danger { color: #c0392b; }
  .empty { color: #666; background: #fff; border-radius: 12px; padding: 24px; text-align: center; }
  .add { display: inline-block; margin-top: 8px; background: #0066ff; color: #fff;
         text-decoration: none; padding: 11px 18px; border-radius: 10px; font-size: 15px; font-weight: 600; }
  .foot { color: #999; font-size: 12px; margin-top: 24px; line-height: 1.6; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Мои Google-аккаунты</h1>
  <p class="sub">Здесь можно подключить несколько своих почт. В Claude выбирай нужную
     параметром <code>account</code> (по метке).</p>
  ${banner}
  ${rows}
  <a class="add" href="${base}/add">+ Добавить аккаунт</a>
  <p class="foot">Токены хранятся зашифрованными на твоём собственном сервере.
     Тот, кто дал тебе эту ссылку, к ним доступа не имеет.</p>
</div>
</body>
</html>`;
}
