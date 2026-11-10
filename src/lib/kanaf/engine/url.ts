import { analyzePhones, type PhoneFinding } from "./phone.ts";
import { scoreLure } from "./lure.ts";

export type UrlVerdict = "clean" | "suspicious" | "malicious";

export type UrlFinding = {
  verdict: UrlVerdict;
  reasons: string[];
  normalized: string;
  host: string;
  hint?: string;
};

const SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
  "tiny.cc",
  "buff.ly",
  "rebrand.ly",
]);

/** Official domains checked by the owner against the public sites. */
export const DEFAULT_TRUSTED_SENDERS = [
  { id: "nama", names: ["نماء", "nama", "nama supply"], domains: ["nama.om", "nws.nama.om"] },
  { id: "ooredoo", names: ["أوريدو", "ooredoo"], domains: ["ooredoo.om", "ooredoo.com"] },
  { id: "omantel", names: ["عمانتل", "omantel"], domains: ["omantel.om", "omantel.com"] },
  { id: "eyewa", names: ["eyewa", "آيوا"], domains: ["eyewa.com"] },
  { id: "bankmuscat", names: ["بنك مسقط", "bank muscat", "bankmuscat"], domains: ["bankmuscat.com"] },
  { id: "bankdhofar", names: ["بنك ظفار", "bank dhofar", "bankdhofar"], domains: ["bankdhofar.com"] },
  { id: "ahlibank", names: ["البنك الأهلي", "ahli bank", "ahlibank"], domains: ["ahlibank.om"] },
  { id: "banknizwa", names: ["بنك نزوى", "bank nizwa", "banknizwa"], domains: ["banknizwa.om"] },
  { id: "nbo", names: ["بنك عمان الوطني", "national bank of oman", "nbo"], domains: ["nbo.om"] },
] as const;

const BRANDS = [
  "nama.om",
  "ooredoo.om",
  "omantel.om",
  "eyewa.com",
  "google.com",
  "microsoft.com",
  "apple.com",
  "paypal.com",
  "bankmuscat.com",
  "bankdhofar.com",
  "ahlibank.om",
  "banknizwa.om",
  "soharinternational.com",
  "instagram.com",
  "whatsapp.com",
  "facebook.com",
];

const HOMO: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  $: "s",
};

export function normalizeUrl(raw: string): { href: string; host: string; hostname: string } | null {
  let s = raw.trim();
  if (!s || s.startsWith("#")) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `http://${s}`;
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname) return null;
  const port = url.port;
  const defaultPort = (url.protocol === "http:" && port === "80") || (url.protocol === "https:" && port === "443") || port === "";
  const host = defaultPort ? hostname : `${hostname}:${port}`;
  let path = url.pathname || "/";
  if (path !== "/" && path.endsWith("/")) path = path.slice(0, -1);
  const href = `${url.protocol}//${host}${path}${url.search}`;
  return { href, host, hostname };
}

export function hostInSet(hostname: string, hosts: Set<string>): boolean {
  let cursor = hostname.toLowerCase();
  while (cursor) {
    if (hosts.has(cursor)) return true;
    const dot = cursor.indexOf(".");
    if (dot < 0) break;
    cursor = cursor.slice(dot + 1);
    if (!cursor.includes(".")) break;
  }
  return false;
}

export function analyzeUrl(raw: string, db: { hosts: Set<string>; urls: Set<string> }): UrlFinding | null {
  const norm = normalizeUrl(raw);
  if (!norm) return null;
  const reasons: string[] = [];
  let verdict: UrlVerdict = "clean";
  if (db.urls.has(norm.href) || hostInSet(norm.hostname, db.hosts)) {
    verdict = "malicious";
    reasons.push("listed");
  }
  if (hidesDestination(raw)) {
    reasons.push("userinfo");
    if (verdict !== "malicious") verdict = "suspicious";
  }
  const lookalike = brandLookalike(norm.hostname);
  if (lookalike) {
    reasons.push("lookalike");
    if (verdict !== "malicious") verdict = "suspicious";
  }
  if (isPublicIp(norm.hostname)) {
    reasons.push("ip-host");
    if (verdict !== "malicious") verdict = "suspicious";
  }
  const embedded = embeddedBrand(norm.hostname);
  if (embedded) {
    reasons.push("brand-host");
    if (verdict !== "malicious") verdict = "suspicious";
  }
  if (verdict !== "clean" && SHORTENERS.has(norm.hostname)) reasons.push("shortener");
  if (verdict !== "clean" && norm.hostname.startsWith("xn--")) reasons.push("punycode");
  return { verdict, reasons, normalized: norm.href, host: norm.hostname, hint: lookalike || embedded || undefined };
}

export function extractUrls(text: string): string[] {
  const found = text.match(/((https?:\/\/|www\.)[^\s<>"']+|((?:[a-z0-9-]+\.)+[a-z]{2,})(?:\/[^\s<>"']*)?)/gi) ?? [];
  return [...new Set(found.map((item) => item.replace(/[),.;]+$/, "")))];
}

export function analyzeMessage(input: {
  sender: string;
  text: string;
  trusted: { names: string[]; domains: string[] }[];
  official?: string[];
  db: { hosts: Set<string>; urls: Set<string> };
}): { verdict: UrlVerdict; reasons: string[]; urls: UrlFinding[]; phones: PhoneFinding[]; fingerprint: string; clause: string } {
  const urls = extractUrls(input.text)
    .map((u) => analyzeUrl(u, input.db))
    .filter((u): u is UrlFinding => u !== null);
  const sender = fold(input.sender);
  const trust = input.trusted.find((row) => row.names.some((name) => fold(name) === sender));
  const reasons = new Set<string>();
  let verdict: UrlVerdict = "clean";
  for (const url of urls) {
    if (url.verdict === "malicious") verdict = "malicious";
    else if (url.verdict === "suspicious" && verdict === "clean") verdict = "suspicious";
    url.reasons.forEach((r) => reasons.add(r));
  }
  if (trust) {
    const outside = urls.filter((u) => !trust.domains.some((d) => u.host === d || u.host.endsWith(`.${d}`)));
    if (outside.length > 0) {
      reasons.add("trusted-sender-off-domain");
      if (verdict === "clean") verdict = "suspicious";
    } else if (verdict !== "malicious") {
      // A trusted sender with only official links is not shown as a threat.
      verdict = "clean";
      reasons.clear();
    }
  }
  const phones = analyzePhones(input.text, input.official ?? []);
  for (const phone of phones) {
    if (phone.verdict === "clean") continue;
    phone.reasons.forEach((reason) => reasons.add(reason));
    if (verdict === "clean") verdict = "suspicious";
  }
  const lure = scoreLure(input.text);
  if (lure && verdict !== "malicious") {
    reasons.add("lure-model");
    verdict = "suspicious";
  }
  if (trust && verdict !== "malicious") {
    const outside = urls.filter((u) => !trust.domains.some((d) => u.host === d || u.host.endsWith(`.${d}`)));
    if (outside.length === 0 && urls.length > 0) {
      verdict = "clean";
      reasons.clear();
    }
  }
  return {
    verdict,
    reasons: [...reasons],
    urls,
    phones,
    fingerprint: "",
    clause: reasons.has("lure-model") && lure ? lure.clause : "",
  };
}

function hidesDestination(raw: string): boolean {
  let s = raw.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `http://${s}`;
  try {
    const parsed = new URL(s);
    return Boolean(parsed.username || parsed.password);
  } catch {
    return false;
  }
}

function isPublicIp(host: string): boolean {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
  const parts = host.split(".").map((part) => Number(part));
  if (parts.some((part) => part > 255)) return false;
  const a = parts[0] ?? 0;
  const b = parts[1] ?? 0;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 192 && b === 168) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 169 && b === 254) return false;
  if (a >= 224) return false;
  return true;
}

function fold(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[أإآ]/g, "ا")
    .replace(/ة/g, "ه")
    .replace(/\s+/g, " ");
}

function squash(host: string): string {
  return [...host.toLowerCase()].map((ch) => HOMO[ch] ?? ch).join("").replace(/[^a-z0-9.]/g, "");
}

const BRAND_TOKENS = ["paypal", "bankmuscat", "bankdhofar", "ahlibank", "banknizwa", "whatsapp", "ooredoo", "omantel", "instagram", "apple", "microsoft"];

function embeddedBrand(host: string): string | null {
  if (BRANDS.some((brand) => host === brand || host.endsWith(`.${brand}`))) return null;
  for (const label of host.split(".")) {
    for (const token of BRAND_TOKENS) {
      if (label === token || label.startsWith(`${token}-`) || label.endsWith(`-${token}`) || label.includes(`-${token}-`)) return token;
    }
  }
  return null;
}

const ARABIC_NAMES = ["بنك مسقط", "بنك ظفار", "البنك الأهلي", "بنك نزوى", "أوريدو", "عمانتل", "نماء"];

function brandLookalike(host: string): string | null {
  const decoded = decodeHost(host);
  const folded = squash(decoded);
  for (const brand of BRANDS) {
    if (host === brand || host.endsWith(`.${brand}`) || decoded === brand || decoded.endsWith(`.${brand}`)) return null;
  }
  for (const brand of BRANDS) {
    const token = brand.split(".")[0] || brand;
    if (folded === squash(brand) || folded.endsWith(`.${squash(brand)}`)) return brand;
    for (const label of folded.split(".")) {
      if (label.length < 5 || label === token) continue;
      const distance = levenshtein(label, token);
      const limit = token.length >= 8 ? 2 : 1;
      if (distance > 0 && distance <= limit) return brand;
    }
  }
  for (const label of decoded.split(".")) {
    const compact = fold(label).replace(/\s+/g, "");
    if (compact.length < 4) continue;
    for (const name of ARABIC_NAMES) {
      const target = fold(name).replace(/\s+/g, "");
      const distance = levenshtein(compact, target);
      if (distance === 0 || (distance === 1 && target.length >= 4)) return name;
    }
  }
  return null;
}

function decodeHost(host: string): string {
  return host
    .split(".")
    .map((label) => (label.startsWith("xn--") ? punyDecode(label.slice(4)) : label))
    .join(".");
}

function punyDecode(input: string): string {
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;
  const out: number[] = [];
  for (const ch of input) {
    if (ch.charCodeAt(0) >= 0x80) return input;
  }
  let i = 0;
  const basic = input.lastIndexOf("-");
  if (basic > 0) {
    for (let k = 0; k < basic; k++) out.push(input.charCodeAt(k));
  }
  let n = initialN;
  let bias = initialBias;
  let index = basic > 0 ? basic + 1 : 0;
  while (index < input.length) {
    const old = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (index >= input.length) return input;
      const c = input.charCodeAt(index++);
      const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
      if (digit >= base) return input;
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const len = out.length + 1;
    bias = adapt(i - old, len, old === 0, damp, skew, base, tMin, tMax);
    n += Math.floor(i / len);
    i %= len;
    out.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...out);
}

function adapt(delta: number, numPoints: number, first: boolean, damp: number, skew: number, base: number, tMin: number, tMax: number): number {
  let value = first ? Math.floor(delta / damp) : delta >> 1;
  value += Math.floor(value / numPoints);
  const gap = base - tMin;
  let k = 0;
  while (value > Math.floor((gap * tMax) / 2)) {
    value = Math.floor(value / gap);
    k += base;
  }
  return k + Math.floor(((gap + 1) * value) / (value + skew));
}

function levenshtein(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 99;
  const prev = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    let last = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, last + cost);
      last = tmp;
    }
  }
  return prev[b.length];
}
