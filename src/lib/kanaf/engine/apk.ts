import { sha256Hex } from "./sha256.ts";

const RSA_OID = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC_OID = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

export type CertHit = {
  sha256: string;
  debug: boolean;
};

export function certificatesFromPkcs(bytes: Uint8Array): CertHit[] {
  const hits: CertHit[] = [];
  const debug = includesAscii(bytes, "Android Debug");
  for (let i = 0; i < bytes.length - 8; i++) {
    if (bytes[i] !== 0x30) continue;
    const parsed = readDer(bytes, i);
    if (!parsed) continue;
    const cert = parsed.bytes;
    if (cert.length < 128 || cert.length > 20000) continue;
    if (!containsOid(cert, RSA_OID) && !containsOid(cert, EC_OID)) continue;
    hits.push({ sha256: sha256Hex(cert), debug: debug || includesAscii(cert, "Android Debug") });
    i += cert.length - 1;
  }
  return hits;
}

function containsOid(bytes: Uint8Array, oid: number[]): boolean {
  outer: for (let i = 0; i + oid.length < bytes.length; i++) {
    for (let j = 0; j < oid.length; j++) if (bytes[i + j] !== oid[j]) continue outer;
    return true;
  }
  return false;
}

function readDer(bytes: Uint8Array, offset: number): { bytes: Uint8Array } | null {
  if (offset >= bytes.length || bytes[offset] !== 0x30) return null;
  const len = readLen(bytes, offset + 1);
  if (!len) return null;
  const end = len.next + len.value;
  if (end > bytes.length) return null;
  return { bytes: bytes.subarray(offset, end) };
}

function readLen(bytes: Uint8Array, offset: number): { value: number; next: number } | null {
  if (offset >= bytes.length) return null;
  const first = bytes[offset];
  if ((first & 0x80) === 0) return { value: first, next: offset + 1 };
  const count = first & 0x7f;
  if (count === 0 || count > 3 || offset + 1 + count > bytes.length) return null;
  let value = 0;
  for (let i = 0; i < count; i++) value = (value << 8) | bytes[offset + 1 + i];
  return { value, next: offset + 1 + count };
}

function includesAscii(bytes: Uint8Array, text: string): boolean {
  const needle = new TextEncoder().encode(text);
  outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

/** Android binary XML string pool. Enough to read permissions and intent names. */
export function axmlStrings(bytes: Uint8Array): string[] {
  if (bytes.length < 28) return [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, true) !== 0x00080003) return [];
  let offset = 8;
  if (offset + 28 > bytes.length) return [];
  const chunkType = view.getUint16(offset, true);
  if (chunkType !== 0x0001) return [];
  const stringCount = view.getUint32(offset + 8, true);
  const flags = view.getUint32(offset + 16, true);
  const stringsStart = view.getUint32(offset + 20, true);
  const utf8 = (flags & (1 << 8)) !== 0;
  if (stringCount > 100000) return [];
  const offsets: number[] = [];
  const table = offset + 28;
  for (let i = 0; i < stringCount; i++) {
    if (table + (i + 1) * 4 > bytes.length) break;
    offsets.push(view.getUint32(table + i * 4, true));
  }
  const pool = offset + stringsStart;
  const out: string[] = [];
  for (const rel of offsets) {
    const start = pool + rel;
    if (start < 0 || start >= bytes.length) continue;
    if (utf8) out.push(readUtf8String(bytes, start));
    else out.push(readUtf16String(bytes, start));
  }
  return out;
}

function readUtf8String(bytes: Uint8Array, offset: number): string {
  let p = offset;
  const skip = (at: number) => ((bytes[at] & 0x80) === 0 ? 1 : 2);
  if (p >= bytes.length) return "";
  p += skip(p);
  if (p >= bytes.length) return "";
  const lenInfo = bytes[p] & 0x80 ? ((bytes[p] & 0x7f) << 8) | bytes[p + 1] : bytes[p];
  p += skip(p);
  const end = Math.min(bytes.length, p + lenInfo);
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(p, end));
}

function readUtf16String(bytes: Uint8Array, offset: number): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (offset + 2 > bytes.length) return "";
  let charCount = view.getUint16(offset, true);
  let p = offset + 2;
  if (charCount & 0x8000) {
    if (p + 2 > bytes.length) return "";
    charCount = ((charCount & 0x7fff) << 16) | view.getUint16(p, true);
    p += 2;
  }
  const byteLen = Math.min(bytes.length - p, charCount * 2);
  return new TextDecoder("utf-16le", { fatal: false }).decode(bytes.subarray(p, p + byteLen));
}

const PACKERS = [
  "com.qihoo.util.",
  "com.secneo.apkwrapper.",
  "com.secneo.",
  "com.bangcle.",
  "com.ijiami.",
  "com.baidu.protect.",
  "com.safedex.",
  "com.tianyu.",
];

function packerName(text: string): string | null {
  if (text.length > 160) return null;
  const lower = text.toLowerCase();
  return PACKERS.find((name) => lower === name.slice(0, -1) || lower.startsWith(name)) ?? null;
}

export type DexSignals = {
  dynamicLoad: boolean;
  packer: string | null;
  shortNameRatio: number;
  stringsSeen: number;
  smsApi: boolean;
  accessApi: boolean;
  hideIcon: boolean;
  adminApi: boolean;
};

function blankDex(): DexSignals {
  return { dynamicLoad: false, packer: null, shortNameRatio: 0, stringsSeen: 0, smsApi: false, accessApi: false, hideIcon: false, adminApi: false };
}

function noteDexString(flags: DexSignals, text: string) {
  if (text.length === 0 || text.length > 180) return;
  if (!flags.smsApi && (text.includes("SmsManager") || text.includes("sendTextMessage") || text.includes("sendMultipartTextMessage"))) flags.smsApi = true;
  if (!flags.accessApi && (text.includes("AccessibilityService") || text.includes("onAccessibilityEvent"))) flags.accessApi = true;
  if (!flags.hideIcon && text.includes("COMPONENT_ENABLED_STATE_DISABLED")) flags.hideIcon = true;
  if (!flags.adminApi && (text.includes("DeviceAdminReceiver") || text.includes("DEVICE_ADMIN_ENABLED"))) flags.adminApi = true;
}

export function dexSignals(bytes: Uint8Array): DexSignals {
  const empty = blankDex();
  if (bytes.length < 0x70) return empty;
  const magic = new TextDecoder("latin1").decode(bytes.subarray(0, 4));
  if (magic !== "dex\n") return scanRaw(bytes);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const endian = view.getUint32(40, true);
  const little = endian === 0x12345678;
  if (!little && endian !== 0x78563412) return scanRaw(bytes);
  const stringCount = view.getUint32(56, little);
  const stringOff = view.getUint32(60, little);
  if (stringCount > 200000 || stringOff > bytes.length) return scanRaw(bytes);
  let dynamic = false;
  let packer: string | null = null;
  let short = 0;
  let seen = 0;
  const flags = blankDex();
  const max = Math.min(stringCount, 80000);
  for (let i = 0; i < max; i++) {
    const idAt = stringOff + i * 4;
    if (idAt + 4 > bytes.length) break;
    const strAt = view.getUint32(idAt, little);
    const text = readUlebString(bytes, strAt);
    if (!text) continue;
    seen++;
    if (text.length <= 2) short++;
    if (text.includes("DexClassLoader") || text.includes("InMemoryDexClassLoader") || text.includes("BaseDexClassLoader")) {
      dynamic = true;
    }
    noteDexString(flags, text);
    if (!packer) packer = packerName(text);
  }
  flags.dynamicLoad = dynamic;
  flags.packer = packer;
  flags.shortNameRatio = seen ? short / seen : 0;
  flags.stringsSeen = seen;
  return flags;
}

function scanRaw(bytes: Uint8Array): DexSignals {
  const text = new TextDecoder("latin1", { fatal: false }).decode(bytes.subarray(0, Math.min(bytes.length, 2_000_000)));
  const flags = blankDex();
  flags.dynamicLoad = text.includes("DexClassLoader");
  flags.packer = PACKERS.find((name) => text.toLowerCase().includes(name)) ?? null;
  noteDexString(flags, text.length > 180 ? text.slice(0, 180) : text);
  const window = 180;
  for (let i = 0; i < text.length && i < 2_000_000; i += 120) {
    noteDexString(flags, text.slice(i, i + window));
    if (flags.smsApi && flags.accessApi && flags.hideIcon && flags.adminApi) break;
  }
  return flags;
}

function readUlebString(bytes: Uint8Array, offset: number): string {
  if (offset < 0 || offset >= bytes.length) return "";
  let p = offset;
  let size = 0;
  let shift = 0;
  for (let k = 0; k < 5 && p < bytes.length; k++) {
    const b = bytes[p++];
    size |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7;
  }
  // MUTF-8 size is in UTF-16 code units; byte length can be larger. Cap the read.
  const end = Math.min(bytes.length, p + size * 3);
  let stop = p;
  while (stop < end && bytes[stop] !== 0) stop++;
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(p, stop));
}
