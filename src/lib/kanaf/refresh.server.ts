import { parseCvd } from "./engine/cvd";
import { ipsToFeed, threatFoxToFeed, urlsToFeed } from "./engine/feeds";
import { normalizeUrl } from "./engine/url";

const DAILY = [
  "https://database.clamav.net/daily.cvd",
  "https://packages.microsoft.com/clamav/daily.cvd",
];

async function pull(url: string): Promise<Uint8Array> {
  const response = await fetch(url, {
    headers: { "user-agent": url.includes("database.clamav.net") ? "ClamAV/1.4.1" : "Kanaf/1.0" },
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok) throw new Error(`${response.status} ${url}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function pullText(url: string): Promise<string> {
  const bytes = await pull(url);
  return new TextDecoder().decode(bytes);
}

function text(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

export async function refreshPart(part: string): Promise<Response> {
  try {
    if (part === "urlhaus") {
      const raw = await pullText("https://urlhaus.abuse.ch/downloads/text/");
      const lines: string[] = [];
      for (const line of raw.split("\n")) {
        const norm = normalizeUrl(line);
        if (norm) lines.push(norm.href);
      }
      return text(lines.join("\n"));
    }
    if (part === "malwarebazaar") {
      const [sha, md5] = await Promise.all([
        pullText("https://bazaar.abuse.ch/export/txt/sha256/recent/"),
        pullText("https://bazaar.abuse.ch/export/txt/md5/recent/"),
      ]);
      const rows: string[] = [];
      for (const line of sha.split("\n")) {
        const hash = line.trim().toLowerCase();
        if (/^[0-9a-f]{64}$/.test(hash)) rows.push(`sha256\t${hash}\t*\tmalwarebazaar\tMalwareBazaar-recent`);
      }
      for (const line of md5.split("\n")) {
        const hash = line.trim().toLowerCase();
        if (/^[0-9a-f]{32}$/.test(hash)) rows.push(`md5\t${hash}\t*\tmalwarebazaar\tMalwareBazaar-recent`);
      }
      return text(rows.join("\n"));
    }
    if (part === "cscb") {
      const raw = await pullText("https://bazaar.abuse.ch/export/csv/cscb/");
      const lines = raw.split("\n").filter((line) => line && !line.startsWith("#") && !line.startsWith('"time'));
      const rows: string[] = [];
      for (const line of lines) {
        const cols = line.split(",");
        const thumb = (cols[2] || "").replaceAll('"', "").trim().toLowerCase();
        const reason = (cols[8] || "CSCB").replaceAll('"', "").trim();
        if (/^[0-9a-f]{64}$/.test(thumb)) rows.push(`${thumb}\t${reason}`);
      }
      return text(rows.join("\n"));
    }
    if (part === "clamav-daily") {
      let last = "unavailable";
      for (const url of DAILY) {
        try {
          const bytes = await pull(url);
          const parsed = await parseCvd(bytes);
          const rows = parsed.records.map(
            (record) => `${record.kind}\t${record.hash}\t${record.size ?? "*"}\tclamav-daily\t${record.name.replaceAll("\t", " ")}`,
          );
          return text(rows.join("\n"));
        } catch (error) {
          last = error instanceof Error ? error.message : "cvd";
        }
      }
      return text(last, 502);
    }
    if (part === "threatfox") return text(threatFoxToFeed(await pullText("https://threatfox.abuse.ch/export/csv/recent/")));
    if (part === "feodo") return text(ipsToFeed(await pullText("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")));
    if (part === "openphish") return text(urlsToFeed(await pullText("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt")));
    if (part === "et-open") return text(ipsToFeed(await pullText("https://rules.emergingthreats.net/blockrules/compromised-ips.txt")));
    return text("unknown source", 404);
  } catch (error) {
    return text(error instanceof Error ? error.message : "refresh failed", 502);
  }
}
