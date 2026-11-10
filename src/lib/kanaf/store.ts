import { create } from "zustand";
import { DEFAULT_TRUSTED_SENDERS } from "./engine/url";
import { emptyDb, type SignatureDb } from "./engine/signatures";
import { DEFAULT_SETTINGS, type AllowItem, type CheckedFile, type Finding, type FolderItem, type LogItem, type ScanSnap, type Settings, type SourceView, type TrustedSender } from "./types";

export type VaultMeta = {
  id: string;
  name: string;
  sha256: string;
  size: number;
  reasonId: string;
  createdAt: number;
};

type State = {
  booted: boolean;
  dbStatus: "loading" | "ready" | "error";
  dbProgress: number;
  hashCount: number;
  sources: SourceView[];
  findings: Finding[];
  vault: VaultMeta[];
  allow: AllowItem[];
  folders: FolderItem[];
  log: LogItem[];
  trusted: TrustedSender[];
  settings: Settings;
  scan: ScanSnap;
  realtime: boolean;
  realtimeNote: string;
  lastClean: boolean;
  lastScan: { files: number; findings: number; skipped: number; downloads: boolean | null } | null;
  checked: CheckedFile[];
  notice: string;
  shell: "web" | "android";
  integrity: "ok" | "repacked" | "unknown" | "";
  device: { lock: boolean; usb: boolean; developer: boolean; patch: string } | null;
};

const idleScan: ScanSnap = {
  running: false,
  phase: "idle",
  mode: null,
  done: 0,
  total: 0,
  current: "",
  found: 0,
  message: "",
};

export const useKanaf = create<State>(() => ({
  booted: false,
  dbStatus: "loading",
  dbProgress: 0,
  hashCount: 0,
  sources: [],
  findings: [],
  vault: [],
  allow: [],
  folders: [],
  log: [],
  trusted: DEFAULT_TRUSTED_SENDERS.map((row) => ({ id: row.id, names: [...row.names], domains: [...row.domains] })),
  settings: DEFAULT_SETTINGS,
  scan: idleScan,
  realtime: false,
  realtimeNote: "",
  lastClean: false,
  lastScan: null,
  checked: [],
  notice: "",
  shell: "web",
  integrity: "",
  device: null,
}));

let database: SignatureDb = emptyDb();
const blobs = new Map<string, Uint8Array>();
const folderHandles = new Map<string, FileSystemDirectoryHandle>();
let scanAbort = false;

export function getDatabase(): SignatureDb {
  return database;
}
export function setDatabase(db: SignatureDb) {
  database = db;
}
export function rememberBlob(id: string, bytes: Uint8Array) {
  if (bytes.byteLength <= 32 * 1024 * 1024) blobs.set(id, bytes);
}
export function takeBlob(id: string): Uint8Array | undefined {
  return blobs.get(id);
}
export function dropBlob(id: string) {
  blobs.delete(id);
}
export function rememberFolder(id: string, handle: FileSystemDirectoryHandle) {
  folderHandles.set(id, handle);
}
export function folderHandle(id: string): FileSystemDirectoryHandle | undefined {
  return folderHandles.get(id);
}
export function requestCancel() {
  scanAbort = true;
}
export function resetCancel() {
  scanAbort = false;
}
export function cancelled(): boolean {
  return scanAbort;
}

export function patch(partial: Partial<State>) {
  useKanaf.setState(partial);
}
