export type ZipLimits = {
  maxEntries: number;
  maxUncompressed: number;
  maxRatio: number;
  ratioFloor: number;
  maxSingle: number;
};

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxEntries: 2000,
  maxUncompressed: 64 * 1024 * 1024,
  maxRatio: 100,
  ratioFloor: 4 * 1024 * 1024,
  maxSingle: 32 * 1024 * 1024,
};

export class ZipLimitError extends Error {
  code: "entries" | "size" | "ratio" | "depth" | "corrupt";
  constructor(code: "entries" | "size" | "ratio" | "depth" | "corrupt") {
    super(code);
    this.name = "ZipLimitError";
    this.code = code;
  }
}

export type ZipEntry = {
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  bytes: Uint8Array;
};

const SIG_EOCD = 0x06054b50;
const SIG_CENTRAL = 0x02014b50;

function u16(view: DataView, offset: number): number {
  return view.getUint16(offset, true);
}
function u32(view: DataView, offset: number): number {
  return view.getUint32(offset, true);
}

export async function readZip(
  data: Uint8Array,
  limits: ZipLimits = DEFAULT_ZIP_LIMITS,
  pick?: (name: string) => boolean,
): Promise<ZipEntry[]> {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let eocd = -1;
  const start = Math.max(0, data.length - 22 - 65535);
  for (let i = data.length - 22; i >= start; i--) {
    if (u32(view, i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new ZipLimitError("corrupt");
  const count = u16(view, eocd + 10);
  const centralSize = u32(view, eocd + 12);
  const centralOffset = u32(view, eocd + 16);
  const entryCap = pick ? 50000 : limits.maxEntries;
  if (count > entryCap) throw new ZipLimitError(pick ? "corrupt" : "entries");
  if (centralOffset + centralSize > data.length) throw new ZipLimitError("corrupt");

  const entries: ZipEntry[] = [];
  let total = 0;
  let cursor = centralOffset;
  for (let n = 0; n < count; n++) {
    if (cursor + 46 > data.length || u32(view, cursor) !== SIG_CENTRAL) throw new ZipLimitError("corrupt");
    const flags = u16(view, cursor + 8);
    const method = u16(view, cursor + 10);
    const compSize = u32(view, cursor + 20);
    const uncompSize = u32(view, cursor + 24);
    const nameLen = u16(view, cursor + 28);
    const extraLen = u16(view, cursor + 30);
    const commentLen = u16(view, cursor + 32);
    const localOffset = u32(view, cursor + 42);
    if (cursor + 46 + nameLen + extraLen + commentLen > centralOffset + centralSize) throw new ZipLimitError("corrupt");
    const name = new TextDecoder("utf-8", { fatal: false }).decode(
      data.subarray(cursor + 46, cursor + 46 + nameLen),
    );
    cursor += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith("/")) continue;
    if (pick && !pick(name)) continue;
    if (uncompSize === 0xffffffff || compSize === 0xffffffff) {
      if (pick) continue;
      throw new ZipLimitError("size");
    }
    if (uncompSize > limits.maxSingle) {
      if (pick) continue;
      throw new ZipLimitError("size");
    }
    total += uncompSize;
    if (total > limits.maxUncompressed) {
      total -= uncompSize;
      if (pick) continue;
      throw new ZipLimitError("size");
    }
    const ratio = uncompSize / Math.max(1, compSize);
    if (uncompSize >= limits.ratioFloor && ratio > limits.maxRatio) {
      if (pick) continue;
      throw new ZipLimitError("ratio");
    }
    if (flags & 0x1) continue;
    if (localOffset + 30 > data.length) throw new ZipLimitError("corrupt");
    const localName = u16(view, localOffset + 26);
    const localExtra = u16(view, localOffset + 28);
    const dataStart = localOffset + 30 + localName + localExtra;
    const compressed = data.subarray(dataStart, dataStart + compSize);
    if (dataStart + compSize > data.length) throw new ZipLimitError("corrupt");
    let bytes: Uint8Array;
    if (method === 0) bytes = compressed;
    else if (method === 8) bytes = await inflateRaw(compressed);
    else continue;
    if (bytes.length !== uncompSize) throw new ZipLimitError("corrupt");
    if (bytes.length > limits.maxSingle) throw new ZipLimitError("size");
    entries.push({
      name,
      method,
      compressedSize: compSize,
      uncompressedSize: bytes.length,
      bytes,
    });
  }
  return entries;
}

async function inflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const copy = new ArrayBuffer(data.byteLength);
  new Uint8Array(copy).set(data);
  const stream = new Blob([copy]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export function isArchiveName(name: string): boolean {
  return /\.(zip|apk|xapk|apks|jar|docx|xlsx|xlsm|xltm|docm|pptx|pptm)$/i.test(name);
}
