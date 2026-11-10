export type HashKind = "md5" | "sha1" | "sha256";

export type HashHit = {
  size: number | null;
  source: string;
  name: string;
};

export type SourceMeta = {
  id: string;
  version: string;
  updatedAt: string;
  count: number;
  license: string;
  terms: string;
  reportedSignatures?: number;
  filtered?: boolean;
  status?: "ready" | "failed" | "missing";
  error?: string;
};

export type SignatureDb = {
  hashes: Map<string, HashHit[]>;
  hosts: Set<string>;
  urls: Set<string>;
  certs: Map<string, string>;
  sources: SourceMeta[];
  builtAt: string;
  hashRecords: number;
};

export function emptyDb(): SignatureDb {
  return {
    hashes: new Map(),
    hosts: new Set(),
    urls: new Set(),
    certs: new Map(),
    sources: [],
    builtAt: "",
    hashRecords: 0,
  };
}

export function lookupHash(db: SignatureDb, kind: HashKind, hash: string, size: number): HashHit | null {
  const rows = db.hashes.get(`${kind}:${hash.toLowerCase()}`);
  if (!rows) return null;
  const sized = rows.find((row) => row.size === null || row.size === size);
  return sized ?? null;
}

export function parseHashTsv(text: string, db: SignatureDb): number {
  let n = 0;
  for (const line of text.split("\n")) {
    if (!line) continue;
    const [kind, hash, size, source, ...nameParts] = line.split("\t");
    if (kind !== "md5" && kind !== "sha1" && kind !== "sha256") continue;
    if (!hash) continue;
    const key = `${kind}:${hash}`;
    const hit: HashHit = {
      size: size === "*" || !/^\d+$/.test(size) ? null : Number(size),
      source: source ?? "",
      name: nameParts.join("\t"),
    };
    const list = db.hashes.get(key);
    if (list) {
      if (!list.some((row) => row.name === hit.name && row.source === hit.source)) list.push(hit);
    } else {
      db.hashes.set(key, [hit]);
      n++;
    }
  }
  db.hashRecords += n;
  return n;
}

export function parseHosts(text: string, db: SignatureDb): number {
  let n = 0;
  for (const line of text.split("\n")) {
    const host = line.trim().toLowerCase();
    if (!host || host.startsWith("#")) continue;
    db.hosts.add(host);
    n++;
  }
  return n;
}

export function parseUrls(text: string, db: SignatureDb): number {
  let n = 0;
  for (const line of text.split("\n")) {
    const url = line.trim();
    if (!url || url.startsWith("#")) continue;
    db.urls.add(url);
    n++;
  }
  return n;
}

export function parseCerts(text: string, db: SignatureDb): number {
  let n = 0;
  for (const line of text.split("\n")) {
    if (!line) continue;
    const [thumb, ...reason] = line.split("\t");
    if (!/^[0-9a-f]{64}$/.test(thumb)) continue;
    db.certs.set(thumb, reason.join("\t") || "CSCB");
    n++;
  }
  return n;
}

export function mergeRecord(db: SignatureDb, kind: HashKind, hash: string, size: number | null, source: string, name: string) {
  const key = `${kind}:${hash.toLowerCase()}`;
  const hit: HashHit = { size, source, name };
  const list = db.hashes.get(key);
  if (list) list.push(hit);
  else db.hashes.set(key, [hit]);
  db.hashRecords++;
}
