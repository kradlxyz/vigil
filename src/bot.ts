import { scanAddress, ScanReport } from "./scanner.js";

/**
 * Format a ScanReport into a concise Telegram Markdown message.
 */
export function formatTelegramReport(report: ScanReport, webBaseUrl: string): string {
  const badge =
    report.riskLevel === "LOW RISK"
      ? "🟢 LOW RISK"
      : report.riskLevel === "MEDIUM RISK"
        ? "🟡 MEDIUM RISK"
        : "🔴 HIGH RISK";

  const lines: string[] = [
    `*Vigil Safety Scan* · ${report.chainName}`,
    `${badge} · Score: *${report.score}/100*`,
    `Address: \`${report.address}\``,
  ];

  if (report.token.isErc20) {
    lines.push(
      `Token: *${report.token.name ?? "Unknown"}* ($${report.token.symbol}) · Supply: ${Number(report.token.totalSupplyFormatted ?? 0).toLocaleString("en-US")}`
    );
  } else {
    lines.push(`Type: ${report.isContract ? `Smart Contract (${report.bytecodeSizeBytes} bytes)` : "EOA Wallet"}`);
  }

  lines.push("");
  for (const c of report.checks) {
    const icon = c.status === "pass" ? "✅" : c.status === "warn" ? "⚠️" : c.status === "fail" ? "🚨" : "ℹ️";
    lines.push(`${icon} *${c.label}*: ${c.detail}`);
  }

  lines.push("");
  lines.push(`Full report: ${webBaseUrl}/?chain=${report.chainId}&address=${report.address}`);
  return lines.join("\n");
}

/**
 * Lightweight long-polling Telegram Bot (activates automatically when TELEGRAM_BOT_TOKEN is set).
 * Commands:
 *   /scan 0x...          (defaults to Base 8453)
 *   /scan base 0x...
 *   /scan robinhood 0x...
 */
export function startTelegramBot(webBaseUrl: string) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token) return;

  console.log("🤖 Vigil Telegram Bot polling started...");
  let offset = 0;

  async function poll() {
    try {
      const res = await fetch(
        `https://api.telegram.org/bot${token}/getUpdates?timeout=25&offset=${offset}`,
        { signal: AbortSignal.timeout(30000) }
      );
      if (!res.ok) return;
      const data = (await res.json()) as {
        ok: boolean;
        result?: Array<{ update_id: number; message?: { chat: { id: number }; text?: string } }>;
      };

      for (const upd of data.result ?? []) {
        offset = upd.update_id + 1;
        const text = upd.message?.text?.trim();
        const chatId = upd.message?.chat.id;
        if (!text || !chatId) continue;

        if (/^\/(start|help)(@\w+)?(\s|$)/i.test(text)) {
          const welcome = [
            `*Vigil · On-Chain Contract & Bytecode Scanner*`,
            `Instant 2-second security audit for *Base Mainnet (8453)* & *Robinhood Chain (4663)*.`,
            ``,
            `*Commands:*`,
            `• \`/scan 0x...\` — Scan on Base Mainnet (default)`,
            `• \`/scan base 0x...\` — Scan on Base Mainnet`,
            `• \`/scan robinhood 0x...\` — Scan on Robinhood Chain`,
            `• Or simply paste any \`0x...\` address!`,
            ``,
            `Web & Free API: ${webBaseUrl}`,
            `Launchpad: https://kradl.xyz`,
          ].join("\n");
          await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              chat_id: chatId,
              text: welcome,
              parse_mode: "Markdown",
              disable_web_page_preview: true,
            }),
          });
          continue;
        }

        const match = text.match(/(?:\/scan(?:@\w+)?\s+)?(?:(base|robinhood|rh|8453|4663)\s+)?(0x[a-fA-F0-9]{40})/i);
        if (!match) continue;

        const chainRaw = (match[1] ?? "base").toLowerCase();
        const chainId = chainRaw === "robinhood" || chainRaw === "rh" || chainRaw === "4663" ? 4663 : 8453;
        const addr = match[2];

        try {
          const report = await scanAddress(chainId, addr);
          const reply = formatTelegramReport(report, webBaseUrl);
          await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ chat_id: chatId, text: reply, parse_mode: "Markdown" }),
          });
        } catch (err) {
          await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              chat_id: chatId,
              text: `Scan error: ${err instanceof Error ? err.message : "Failed to scan address"}`,
            }),
          });
        }
      }
    } catch {
      // transient network timeout; retry on next tick
    } finally {
      setTimeout(poll, 1000);
    }
  }

  poll();
}
