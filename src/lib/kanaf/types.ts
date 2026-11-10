import type { SourceMeta } from "./engine/signatures";

export type Finding = {
  id: string;
  kind: "file" | "url" | "message";
  name: string;
  path: string;
  size: number;
  sha256: string;
  md5: string;
  verdict: "malicious" | "suspicious";
  reasonId: string;
  detail: string;
  permissions: string[];
  createdAt: number;
  sender?: string;
  folderId?: string;
  segments?: string[];
  packageName?: string;
};

export type AllowItem = { id: string; sha256: string; name: string; createdAt: number };
export type FolderItem = { id: string; name: string; handle?: FileSystemDirectoryHandle };
export type LogItem = {
  id: string;
  mode: "deep" | "quick" | "custom" | "scheduled" | "live";
  startedAt: number;
  finishedAt: number;
  files: number;
  findings: number;
  skipped: number;
  status: "done" | "cancelled" | "error";
};

export type TrustedSender = { id: string; names: string[]; domains: string[] };

export type CheckedFile = {
  name: string;
  size: number;
  sha256: string;
  kind: "apk" | "zip" | "office" | "image" | "pdf" | "rar" | "ole" | "other";
  verdict: "malicious" | "suspicious" | "clean" | "skipped";
};

export type OfficialNumber = { id: string; label: string; e164: string };

export type Settings = {
  wifiOnly: boolean;
  cloudFeeds: boolean;
  lastFeeds: number;
  scheduleEnabled: boolean;
  every: "day" | "week";
  chargingOnly: boolean;
  lastScheduled: number;
  officialNumbers: OfficialNumber[];
  blockedNumbers: string[];
  cloudKey: string;
};

export type ScanSnap = {
  running: boolean;
  phase: "idle" | "enum" | "hash" | "done" | "cancelled" | "error";
  mode: LogItem["mode"] | null;
  done: number;
  total: number;
  current: string;
  found: number;
  message: string;
};

export type SourceView = SourceMeta & { state: "missing" | "loading" | "ready" | "failed"; error?: string };

export const DEFAULT_SETTINGS: Settings = {
  wifiOnly: true,
  cloudFeeds: false,
  lastFeeds: 0,
  scheduleEnabled: false,
  every: "day",
  chargingOnly: false,
  lastScheduled: 0,
  officialNumbers: [],
  blockedNumbers: [],
  cloudKey: "",
};
