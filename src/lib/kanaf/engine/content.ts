import type { SignatureDb } from "./signatures.ts";
import { analyzeUrl, extractUrls } from "./url.ts";

export type FileKind = "apk" | "zip" | "office" | "image" | "pdf" | "rar" | "ole" | "other";

export function classify(name: string, bytes: Uint8Array): FileKind {
  const lower = name.toLowerCase();
  if (/\.(apk|xapk|apks)$/.test(lower)) return "apk";
  if (/\.(docx|xlsx|xlsm|xltm|docm|pptx|pptm)$/.test(lower)) return "office";
  if (isRar(bytes) || /\.rar$/.test(lower)) return "rar";
  if (isPdf(bytes) || /\.pdf$/.test(lower)) return "pdf";
  if (isOle(bytes) || /\.(doc|xls|ppt)$/.test(lower)) return "ole";
  if (isImage(lower, bytes)) return "image";
  if (/\.(zip|jar)$/.test(lower) || looksLikeZip(bytes)) return "zip";
  return "other";
}

export function looksLikeZip(bytes: Uint8Array): boolean {
  return bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && (bytes[2] === 0x03 || bytes[2] === 0x05 || bytes[2] === 0x07);
}

export function isRar(bytes: Uint8Array): boolean {
  return bytes.length > 6 && bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72 && bytes[3] === 0x21;
}

function isPdf(bytes: Uint8Array): boolean {
  return bytes.length > 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
}

function isOle(bytes: Uint8Array): boolean {
  return bytes.length > 4 && bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0;
}

function isImage(lower: string, bytes: Uint8Array): boolean {
  if (bytes.length > 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return true;
  if (bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8) return true;
  return /\.(png|jpe?g|gif|webp)$/.test(lower);
}

export function shouldOpenOfficeEntry(name: string): boolean {
  return /\.(exe|dll|apk|jar|zip|js|vbs|bat|cmd|scr|hta|lnk)$/i.test(name) || /(^|\/)vbaProject\.bin$/i.test(name);
}

export function officeRisks(
  entries: { name: string; bytes: Uint8Array }[],
  db: SignatureDb,
): { reasonId: string; detail: string }[] {
  const risks: { reasonId: string; detail: string }[] = [];
  if (entries.some((entry) => /(^|\/)vbaProject\.bin$/i.test(entry.name))) risks.push({ reasonId: "macro", detail: "vba" });
  for (const entry of entries) {
    if (!/\.rels$/i.test(entry.name) || entry.bytes.length > 200_000) continue;
    const text = new TextDecoder("utf-8", { fatal: false }).decode(entry.bytes);
    for (const raw of extractUrls(text)) {
      const verdict = analyzeUrl(raw, db);
      if (!verdict || verdict.verdict === "clean") continue;
      risks.push({ reasonId: "doc-link", detail: verdict.host });
      return risks;
    }
  }
  return risks;
}

export function looseRisks(name: string, bytes: Uint8Array): { reasonId: string; detail: string }[] {
  const risks: { reasonId: string; detail: string }[] = [];
  if (isImage(name.toLowerCase(), bytes) && imageTrailer(bytes)) risks.push({ reasonId: "polyglot", detail: "" });
  const pdf = isPdf(bytes) || name.toLowerCase().endsWith(".pdf") ? pdfRisk(bytes) : null;
  if (pdf) risks.push({ reasonId: pdf, detail: "" });
  if ((isOle(bytes) || /\.(doc|xls|ppt)$/i.test(name)) && oleMacro(bytes)) risks.push({ reasonId: "macro", detail: "ole" });
  return risks;
}

function imageTrailer(bytes: Uint8Array): boolean {
  if (bytes[0] === 0x89 && bytes[1] === 0x50) {
    const marker = [0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82];
    let at = -1;
    for (let i = bytes.length - marker.length; i >= 8; i--) {
      let same = true;
      for (let j = 0; j < marker.length; j++) if (bytes[i + j] !== marker[j]) same = false;
      if (same) {
        at = i + marker.length;
        break;
      }
    }
    if (at < 0) return false;
    return payload(bytes.subarray(at));
  }
  if (bytes[0] === 0xff && bytes[1] === 0xd8) {
    let end = -1;
    for (let i = bytes.length - 2; i >= 2; i--) {
      if (bytes[i] === 0xff && bytes[i + 1] === 0xd9) {
        end = i + 2;
        break;
      }
    }
    if (end < 0) return false;
    return payload(bytes.subarray(end));
  }
  return false;
}

function payload(trailer: Uint8Array): boolean {
  let i = 0;
  while (i < trailer.length && trailer[i] <= 32) i++;
  const b = trailer.subarray(i);
  if (b.length < 16) return false;
  if (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) return true;
  if (b[0] === 0x4d && b[1] === 0x5a) return true;
  if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return true;
  if (b[0] === 0x64 && b[1] === 0x65 && b[2] === 0x78 && b[3] === 0x0a) return true;
  return false;
}

function pdfRisk(bytes: Uint8Array): "pdf-launch" | "pdf-active" | null {
  const text = new TextDecoder("latin1").decode(bytes.subarray(0, Math.min(bytes.length, 1_500_000)));
  if (/\/Launch\b/.test(text)) return "pdf-launch";
  if (/\/OpenAction\b/.test(text) && (/\/JavaScript\b/.test(text) || /\/JS\b/.test(text))) return "pdf-active";
  return null;
}

function oleMacro(bytes: Uint8Array): boolean {
  const text = new TextDecoder("latin1").decode(bytes.subarray(0, Math.min(bytes.length, 4_000_000)));
  return text.includes("_VBA_PROJECT");
}
