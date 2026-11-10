const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
  20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10,
  15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32);

function rotl(x: number, n: number): number {
  return (x << n) | (x >>> (32 - n));
}

/** Incremental MD5. Output is lowercase hex. */
export class Md5 {
  private a = 0x67452301;
  private b = 0xefcdab89;
  private c = 0x98badcfe;
  private d = 0x10325476;
  private bytes = 0;
  private buf = new Uint8Array(64);
  private len = 0;

  update(chunk: Uint8Array): void {
    this.bytes += chunk.length;
    let offset = 0;
    if (this.len > 0) {
      const need = 64 - this.len;
      const take = Math.min(need, chunk.length);
      this.buf.set(chunk.subarray(0, take), this.len);
      this.len += take;
      offset = take;
      if (this.len === 64) {
        this.block(this.buf);
        this.len = 0;
      }
    }
    while (offset + 64 <= chunk.length) {
      this.block(chunk.subarray(offset, offset + 64));
      offset += 64;
    }
    if (offset < chunk.length) {
      this.buf.set(chunk.subarray(offset), 0);
      this.len = chunk.length - offset;
    }
  }

  private block(block: Uint8Array): void {
    const m = new Uint32Array(16);
    for (let i = 0; i < 16; i++) {
      const j = i * 4;
      m[i] = block[j] | (block[j + 1] << 8) | (block[j + 2] << 16) | (block[j + 3] << 24);
    }
    let a = this.a;
    let b = this.b;
    let c = this.c;
    let d = this.d;
    for (let i = 0; i < 64; i++) {
      let f = 0;
      let g = 0;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }
      const next = (a + f + K[i] + m[g]) >>> 0;
      a = d;
      d = c;
      c = b;
      b = (b + rotl(next, S[i])) >>> 0;
    }
    this.a = (this.a + a) >>> 0;
    this.b = (this.b + b) >>> 0;
    this.c = (this.c + c) >>> 0;
    this.d = (this.d + d) >>> 0;
  }

  digest(): Uint8Array {
    const bits = this.bytes * 8;
    const pad = new Uint8Array(this.len < 56 ? 64 - this.len : 128 - this.len);
    pad[0] = 0x80;
    const view = new DataView(pad.buffer);
    view.setUint32(pad.length - 8, bits >>> 0, true);
    view.setUint32(pad.length - 4, Math.floor(bits / 2 ** 32), true);
    this.update(pad);
    const out = new Uint8Array(16);
    const words = [this.a, this.b, this.c, this.d];
    for (let i = 0; i < 4; i++) {
      out[i * 4] = words[i] & 0xff;
      out[i * 4 + 1] = (words[i] >>> 8) & 0xff;
      out[i * 4 + 2] = (words[i] >>> 16) & 0xff;
      out[i * 4 + 3] = (words[i] >>> 24) & 0xff;
    }
    return out;
  }

  hex(): string {
    return [...this.digest()].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
}

export function md5Hex(data: Uint8Array): string {
  const h = new Md5();
  h.update(data);
  return h.hex();
}
