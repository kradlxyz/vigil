import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanAddress, SUPPORTED_CHAINS, ScanReport } from "./scanner.js";
import { startTelegramBot } from "./bot.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3010);
const WEB_BASE_URL = process.env.WEB_BASE_URL || "https://scan.kradl.xyz";
const PUBLIC_HTML_PATH = path.resolve(__dirname, "../public/index.html");

// Simple bounded TTL cache (30s) & per-IP rate limiter (30 req/min)
const scanCache = new Map<string, { report: ScanReport; expiresAt: number }>();
const rateHits = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  if (rateHits.size > 5000) rateHits.clear();
  const entry = rateHits.get(ip);
  if (!entry || entry.resetAt <= now) {
    rateHits.set(ip, { count: 1, resetAt: now + 60_000 });
    return true;
  }
  if (entry.count >= 30) return false;
  entry.count += 1;
  return true;
}

function sendJson(res: http.ServerResponse, status: number, body: unknown) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  if (!req.url) return sendJson(res, 400, { error: "Bad request" });
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
    });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const pathname = url.pathname;

  if (pathname === "/api/health") {
    return sendJson(res, 200, {
      status: "ok",
      service: "vigil-scanner",
      chains: Object.values(SUPPORTED_CHAINS).map((c) => ({ id: c.id, name: c.name })),
      timestamp: new Date().toISOString(),
    });
  }

  const scanMatch = pathname.match(/^\/api\/scan\/(\d+)\/(0x[a-fA-F0-9]{40})$/);
  if (scanMatch) {
    const ip =
      String(req.headers["cf-connecting-ip"] || req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown")
        .split(",")[0]
        .trim();
    if (!checkRateLimit(ip)) {
      return sendJson(res, 429, { error: "Rate limit exceeded (30 scans/min). Try again shortly." });
    }

    const chainId = Number(scanMatch[1]);
    const address = scanMatch[2].toLowerCase();
    const cacheKey = `${chainId}:${address}`;
    const cached = scanCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return sendJson(res, 200, { ...cached.report, cached: true });
    }

    try {
      const report = await scanAddress(chainId, address);
      if (scanCache.size > 500) scanCache.clear();
      scanCache.set(cacheKey, { report, expiresAt: Date.now() + 30_000 });
      return sendJson(res, 200, { ...report, cached: false });
    } catch (err) {
      return sendJson(res, 400, {
        error: err instanceof Error ? err.message : "Failed to scan address",
      });
    }
  }

  if (pathname === "/" || pathname.startsWith("/scan/")) {
    try {
      const html = fs.readFileSync(PUBLIC_HTML_PATH, "utf8");
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
      });
      return res.end(html);
    } catch {
      return sendJson(res, 500, { error: "UI bundle missing" });
    }
  }

  return sendJson(res, 404, { error: "Not found" });
});

server.listen(PORT, () => {
  console.log(`🛡️  Vigil Scanner listening on http://0.0.0.0:${PORT}`);
  startTelegramBot(WEB_BASE_URL);
});
