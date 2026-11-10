import { parseHashTsv, parseHosts, parseUrls, type SignatureDb } from "./signatures.ts";
import { normalizeUrl } from "./url.ts";

/** Lines shaped as `U href`, `H host`, or a hash TSV row. Returns how many records were added. */
export function applyFeed(text: string, db: SignatureDb): number {
  const urls: string[] = [];
  const hosts: string[] = [];
  const hashes: string[] = [];
  for (const line of text.split("\n")) {
    if (line.startsWith("U ")) urls.push(line.slice(2).trim());
    else if (line.startsWith("H ")) hosts.push(line.slice(2).trim().toLowerCase());
    else if (/^(md5|sha1|sha256)\t/.test(line)) hashes.push(line);
  }
  return parseUrls(urls.join("\n"), db) + parseHosts(hosts.join("\n"), db) + parseHashTsv(hashes.join("\n"), db);
}

export function urlsToFeed(raw: string): string {
  if (/<html/i.test(raw.slice(0, 200))) throw new Error("not a url feed");
  const lines: string[] = [];
  for (const line of raw.split("\n")) {
    const norm = normalizeUrl(line.trim());
    if (norm) lines.push(`U ${norm.href}`);
  }
  return lines.join("\n");
}

export function ipsToFeed(raw: string): string {
  const lines: string[] = [];
  for (const line of raw.split("\n")) {
    const ip = line.trim();
    if (!ip || ip.startsWith("#")) continue;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) lines.push(`H ${ip}`);
  }
  return lines.join("\n");
}

/** ThreatFox recent CSV. Confidence below 75 is ignored so a weak report is not a hit. */
export function threatFoxToFeed(raw: string): string {
  const lines: string[] = [];
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('"')) continue;
    const cols = trimmed.replace(/^"|"$/g, "").split(/"\s*,\s*"/).map((col) => col.trim());
    if (cols.length < 10) continue;
    const value = cols[2] ?? "";
    const type = cols[3] ?? "";
    const confidence = Number(cols[9]);
    if (!Number.isFinite(confidence) || confidence < 75) continue;
    const name = (cols[7] || cols[5] || "ThreatFox").replaceAll("\t", " ").slice(0, 80);
    if (type === "url") {
      const norm = normalizeUrl(value);
      if (norm) lines.push(`U ${norm.href}`);
    } else if (type === "domain" && value.includes(".")) {
      lines.push(`H ${value.toLowerCase()}`);
    } else if (type === "ip:port") {
      const ip = value.split(":")[0] ?? "";
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) lines.push(`H ${ip}`);
    } else if (type === "sha256_hash" && /^[0-9a-f]{64}$/i.test(value)) {
      lines.push(`sha256\t${value.toLowerCase()}\t*\tthreatfox\t${name}`);
    } else if (type === "md5_hash" && /^[0-9a-f]{32}$/i.test(value)) {
      lines.push(`md5\t${value.toLowerCase()}\t*\tthreatfox\t${name}`);
    }
  }
  return lines.join("\n");
}
