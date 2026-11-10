import { idbDelete, idbPut } from "./idb";

export type VaultRecord = {
  id: string;
  name: string;
  sha256: string;
  size: number;
  reasonId: string;
  createdAt: number;
  iv: ArrayBuffer;
  data: ArrayBuffer;
};

async function vaultKey(): Promise<CryptoKey> {
  const rows = await import("./idb").then((m) => m.idbAll<{ id: string; key?: CryptoKey }>("meta"));
  const existing = rows.find((row) => row.id === "vault-key" && row.key);
  if (existing?.key) return existing.key;
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await idbPut("meta", { id: "vault-key", key });
  return key;
}

export async function seal(bytes: Uint8Array, meta: Omit<VaultRecord, "iv" | "data">): Promise<VaultRecord> {
  const key = await vaultKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const copy = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, copy);
  const record: VaultRecord = { ...meta, iv: iv.buffer, data: cipher };
  await idbPut("quarantine", record);
  return record;
}

export async function openVault(record: VaultRecord): Promise<Uint8Array> {
  const key = await vaultKey();
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(record.iv) }, key, record.data);
  return new Uint8Array(plain);
}

export async function destroyVault(id: string): Promise<void> {
  await idbDelete("quarantine", id);
}
