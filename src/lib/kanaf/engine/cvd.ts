import { md5Hex } from "./md5.ts";

const N = BigInt(
  "118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037",
);
const E = 100001027n;
const ALPH = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

export class CvdError extends Error {
  code: "bad-magic" | "bad-md5" | "bad-signature" | "bad-archive";
  constructor(code: "bad-magic" | "bad-md5" | "bad-signature" | "bad-archive") {
    super(code);
    this.name = "CvdError";
    this.code = code;
  }
}

export type CvdHeader = {
  built: string;
  version: string;
  reportedSignatures: number;
  functionalityLevel: string;
  md5: string;
  builder: string;
  buildTime: number;
};

export type HashRecord = {
  kind: "md5" | "sha1" | "sha256";
  hash: string;
  size: number | null;
  name: string;
};

/**
 * Legacy freshclam check: custom 6-bit alphabet, then p = c^e mod n,
 * and the 16-byte result must equal the MD5 of the gzip body.
 */
export function verifyClamAvDsig(md5HexDigest: string, dsig: string): boolean {
  if (!/^[0-9a-f]{32}$/i.test(md5HexDigest) || dsig.length < 8) return false;
  let c = 0n;
  for (let i = 0; i < dsig.length; i++) {
    const dec = ALPH.indexOf(dsig[i]);
    if (dec < 0) return false;
    c += BigInt(dec) << (BigInt(6) * BigInt(i));
  }
  const p = modPow(c, E, N);
  const hex = p.toString(16).padStart(32, "0");
  if (hex.length > 32) return false;
  return hex === md5HexDigest.toLowerCase();
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

export function parseCvdHeader(file: Uint8Array): { header: CvdHeader; body: Uint8Array } {
  if (file.length < 520) throw new CvdError("bad-magic");
  const headBytes = file.subarray(0, 512);
  const zero = headBytes.indexOf(0);
  const text = new TextDecoder("latin1").decode(zero >= 0 ? headBytes.subarray(0, zero) : headBytes).trim();
  const parts = text.split(":");
  if (parts[0] !== "ClamAV-VDB" || parts.length < 9) throw new CvdError("bad-magic");
  const body = file.subarray(512);
  const header: CvdHeader = {
    built: parts[1],
    version: parts[2],
    reportedSignatures: Number(parts[3]),
    functionalityLevel: parts[4],
    md5: parts[5].toLowerCase(),
    builder: parts[7],
    buildTime: Number(parts[8]),
  };
  if (md5Hex(body) !== header.md5) throw new CvdError("bad-md5");
  if (!verifyClamAvDsig(header.md5, parts[6])) throw new CvdError("bad-signature");
  return { header, body };
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(copy).set(bytes);
  return copy;
}

export async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([toArrayBuffer(bytes)]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export function extractHashRecords(tar: Uint8Array): HashRecord[] {
  const records: HashRecord[] = [];
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const name = readString(header, 0, 100);
    const size = parseInt(readString(header, 124, 12).trim(), 8);
    const typeflag = header[156];
    const prefix = readString(header, 345, 155);
    const full = prefix ? `${prefix}/${name}` : name;
    offset += 512;
    if (!Number.isFinite(size) || size < 0 || offset + size > tar.length) {
      throw new CvdError("bad-archive");
    }
    const data = tar.subarray(offset, offset + size);
    const blocks = Math.ceil(size / 512);
    offset += blocks * 512;
    const base = full.split("/").pop() ?? full;
    if (typeflag !== 0 && typeflag !== 48) continue;
    if (!base.endsWith(".hdb") && !base.endsWith(".hsb")) continue;
    const text = new TextDecoder("utf-8").decode(data);
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const bits = trimmed.split(":");
      if (bits.length < 3) continue;
      const hash = bits[0].toLowerCase();
      const sizeField = bits[1];
      const malname = bits[2];
      const kind = hash.length === 32 ? "md5" : hash.length === 40 ? "sha1" : hash.length === 64 ? "sha256" : null;
      if (!kind || !/^[0-9a-f]+$/.test(hash)) continue;
      const fileSize = /^\d+$/.test(sizeField) ? Number(sizeField) : null;
      records.push({ kind, hash, size: fileSize, name: malname });
    }
  }
  return records;
}

function readString(bytes: Uint8Array, start: number, length: number): string {
  let end = start;
  const stop = start + length;
  while (end < stop && bytes[end] !== 0) end++;
  return new TextDecoder("latin1").decode(bytes.subarray(start, end));
}

export async function parseCvd(file: Uint8Array): Promise<{ header: CvdHeader; records: HashRecord[] }> {
  const { header, body } = parseCvdHeader(file);
  let tar: Uint8Array;
  try {
    tar = await gunzip(body);
  } catch {
    throw new CvdError("bad-archive");
  }
  return { header, records: extractHashRecords(tar) };
}
