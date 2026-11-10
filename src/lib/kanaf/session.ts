import { assetUrl } from "./asset";
import { parseCvd } from "./engine/cvd";
import { eicarBytes } from "./engine/eicar";
import { classify } from "./engine/content";
import { DEEP_LIMITS, hashBuffer, inspectBytes, QUICK_LIMITS } from "./engine/scan";
import {
  emptyDb,
  lookupHash,
  parseCerts,
  parseHashTsv,
  parseHosts,
  parseUrls,
  type SignatureDb,
  type SourceMeta,
} from "./engine/signatures";
import { scoreBehavior } from "./engine/behavior";
import { ipsToFeed, threatFoxToFeed, urlsToFeed } from "./engine/feeds";
import { analyzeMessage, analyzeUrl, normalizeUrl } from "./engine/url";
import { sha256Hex } from "./engine/sha256";
import { idbAll, idbDelete, idbPut } from "./idb";
import {
  cancelled,
  dropBlob,
  folderHandle,
  getDatabase,
  patch,
  rememberBlob,
  rememberFolder,
  requestCancel,
  resetCancel,
  setDatabase,
  takeBlob,
  useKanaf,
} from "./store";
import type { AllowItem, CheckedFile, Finding, FolderItem, LogItem, Settings, TrustedSender } from "./types";
import { DEFAULT_SETTINGS } from "./types";
import { destroyVault, openVault, seal, type VaultRecord } from "./vault";

type PickerWindow = Window & {
  showDirectoryPicker?: (options?: { mode?: "read" | "readwrite"; startIn?: string }) => Promise<FileSystemDirectoryHandle>;
  showOpenFilePicker?: (options?: { multiple?: boolean; mode?: "read" | "readwrite" }) => Promise<FileSystemFileHandle[]>;
  FileSystemObserver?: new (
    callback: (records: { changedHandle?: FileSystemHandle; type?: string }[]) => void,
  ) => { observe: (handle: FileSystemHandle, options?: { recursive?: boolean }) => Promise<void>; disconnect: () => void };
};

type NativePick = { name: string; path: string; url: string; pkg?: string; perms?: string[] };

type DeviceStatus = { lock: boolean; usb: boolean; developer: boolean; patch: string };

type KanafNative = {
  pick: (kind: string, mode: string) => void;
  shell?: () => string;
  listTargets?: (mode: string) => string;
  listMessages?: () => string;
  listBehavior?: () => string;
  clipboard?: () => string;
  askSms?: () => void;
  fetchUrl?: (id: string, url: string) => void;
  network?: () => string;
  deviceStatus?: () => string;
  setWatch?: (on: boolean) => string;
  watching?: () => string;
  askNotify?: () => void;
  uninstall?: (pkg: string) => void;
  openSettings?: (kind: string) => void;
  integrity?: () => string;
  note?: (body: string) => void;
  notices?: () => string;
  pendingNotice?: () => string;
  pendingHashes?: () => string;
  pendingCerts?: () => string;
  askCamera?: () => void;
  pickNumbers?: () => void;
  clearPending?: () => void;
  setCallPolicy?: (json: string) => void;
  callRole?: () => string;
  askCallRole?: () => void;
  clearOwnCache?: () => string;
  listJunk?: () => string;
  deleteJunk?: (json: string) => string;
  saveText?: (name: string, body: string) => string;
};

function kanafNative(): KanafNative | null {
  if (typeof window === "undefined") return null;
  const native = (window as Window & { KanafNative?: KanafNative }).KanafNative;
  if (!native || typeof native.pick !== "function") return null;
  return native;
}

let nativeWait: ((files: NativePick[] | null) => void) | null = null;
let netWait: ((id: string, ok: boolean) => void) | null = null;
let netStatus = "";
let permWait: ((ok: boolean) => void) | null = null;

if (typeof window !== "undefined") {
  const cryptoObj = globalThis.crypto;
  if (cryptoObj && typeof cryptoObj.randomUUID !== "function") {
    const fallback = (): `${string}-${string}-${string}-${string}-${string}` => {
      const bytes = new Uint8Array(16);
      if (typeof cryptoObj.getRandomValues === "function") cryptoObj.getRandomValues(bytes);
      else for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
      bytes[6] = (bytes[6] & 0x0f) | 0x40;
      bytes[8] = (bytes[8] & 0x3f) | 0x80;
      const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
      return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    };
    try {
      Object.defineProperty(cryptoObj, "randomUUID", { value: fallback });
    } catch {
      cryptoObj.randomUUID = fallback;
    }
  }
  (window as Window & { __kanafDeliver?: (payload: string | null) => void }).__kanafDeliver = (payload) => {
    const wait = nativeWait;
    nativeWait = null;
    if (!wait) return;
    if (!payload) {
      wait(null);
      return;
    }
    try {
      const parsed = JSON.parse(payload) as { files?: NativePick[] };
      wait(Array.isArray(parsed.files) ? parsed.files : []);
    } catch {
      wait(null);
    }
  };
  (window as Window & { __kanafNet?: (id: string, ok: boolean, status?: string) => void }).__kanafNet = (id, ok, status) => {
    netStatus = status || "";
    netWait?.(id, ok);
  };
  (window as Window & { __kanafPerm?: (ok: boolean) => void }).__kanafPerm = (ok) => {
    const wait = permWait;
    permWait = null;
    wait?.(ok);
  };
  (window as Window & { __kanafLive?: (id: string, name: string) => void }).__kanafLive = (id, name) => {
    const url = `https://appassets.androidplatform.net/__apk/${encodeURIComponent(id)}`;
    void scanFiles("live", [{ name: name || id, path: name || id, url }]);
  };
  (window as Window & { __kanafNotice?: (text: string) => void }).__kanafNotice = (text) => {
    void reviewNotice(String(text || ""));
  };
  (window as Window & { __kanafHash?: (name: string, sha: string, size: number) => void }).__kanafHash = (name, sha, size) => {
    void reviewHash(String(name || ""), String(sha || ""), Number(size) || 0);
  };
}

const waitingHashes: { name: string; sha: string; size: number }[] = [];
let waitingNotice = "";

async function reviewHash(name: string, sha: string, size: number) {
  if (!/^[a-f0-9]{64}$/.test(sha)) return;
  if (useKanaf.getState().dbStatus !== "ready") {
    waitingHashes.push({ name, sha, size });
    return;
  }
  const hit = lookupHash(getDatabase(), "sha256", sha, size);
  if (!hit) return;
  kanafNative()?.note?.(name);
  if (useKanaf.getState().findings.some((item) => item.sha256 === sha)) return;
  await addFindings(
    [
      {
        kind: "file",
        name: name || sha.slice(0, 12),
        path: name || sha,
        size,
        sha256: sha,
        md5: "",
        verdict: "malicious",
        reasonId: /eicar/i.test(hit.name) ? "eicar" : "hash-match",
        detail: hit.name,
        permissions: [],
      },
    ],
    [{ idHint: sha }],
  );
}

async function reviewNotice(text: string) {
  const sample = text.slice(0, 4000);
  if (!sample.trim()) return;
  if (useKanaf.getState().dbStatus !== "ready") {
    waitingNotice = sample;
    return;
  }
  const result = inspectMessage("notification", sample);
  for (const url of result.urls) {
    if (url.verdict === "clean") continue;
    const fingerprint = sha256Hex(new TextEncoder().encode(url.normalized));
    await keepMessageFinding("notification", fingerprint, url.reasons[0] || "listed", url.host, url.verdict);
  }
}

async function drainNative() {
  const native = kanafNative();
  const notice = waitingNotice || native?.pendingNotice?.() || "";
  waitingNotice = "";
  let rows: { name?: string; sha?: string; size?: number }[] = [];
  try {
    rows = JSON.parse(native?.pendingHashes?.() || "[]") as typeof rows;
  } catch {
    rows = [];
  }
  let certs: { pkg?: string; before?: string; after?: string }[] = [];
  try {
    certs = JSON.parse(native?.pendingCerts?.() || "[]") as typeof certs;
  } catch {
    certs = [];
  }
  native?.clearPending?.();
  for (const row of waitingHashes.splice(0)) rows.push(row);
  if (notice) await reviewNotice(notice);
  for (const row of rows) {
    if (!row.sha) continue;
    await reviewHash(row.name || "", row.sha, Number(row.size) || 0);
  }
  for (const row of certs) {
    if (!row.pkg || !row.before || !row.after || row.before === row.after) continue;
    const after = row.after;
    if (useKanaf.getState().findings.some((item) => item.reasonId === "cert-changed" && item.path === `apps/${row.pkg}` && item.detail.endsWith(after.slice(0, 12)))) continue;
    await addFindings(
      [
        {
          kind: "file",
          name: row.pkg,
          path: `apps/${row.pkg}`,
          size: 0,
          sha256: after,
          md5: "",
          verdict: "suspicious",
          reasonId: "cert-changed",
          detail: `${row.before.slice(0, 12)} → ${after.slice(0, 12)}`,
          permissions: [],
          packageName: row.pkg,
        },
      ],
      [{ idHint: row.pkg }],
    );
  }
}

function filesFromNative(kind: "folder" | "files", mode: string): Promise<NativePick[] | null | "absent"> {
  const native = kanafNative();
  if (!native) return Promise.resolve("absent");
  return new Promise((resolve) => {
    nativeWait = resolve;
    native.pick(kind, mode);
  });
}

let observer: { disconnect: () => void } | null = null;
let booted = false;

function readIntegrity(): "ok" | "repacked" | "unknown" {
  const native = kanafNative();
  if (!native?.integrity) return "unknown";
  const value = native.integrity();
  if (value === "ok" || value === "repacked") return value;
  return "unknown";
}

async function maybeRefreshFeeds(): Promise<void> {
  const { settings, integrity } = useKanaf.getState();
  if (!settings.cloudFeeds) return;
  if (integrity === "repacked") {
    patch({ notice: "repacked" });
    return;
  }
  if (Date.now() - settings.lastFeeds < 24 * 60 * 60 * 1000) return;
  await refreshSources(false);
}

export async function boot() {
  if (booted) return;
  booted = true;
  const native = kanafNative();
  if (native?.shell?.() === "android") {
    let device: DeviceStatus | null = null;
    try {
      device = native.deviceStatus ? (JSON.parse(native.deviceStatus()) as DeviceStatus) : null;
    } catch {
      device = null;
    }
    const watching = native.watching?.() === "on";
    patch({ shell: "android", device, realtime: watching, realtimeNote: watching ? "watching" : "" });
  }
  const [findings, vault, allow, log, meta, folders] = await Promise.all([
    idbAll<Finding>("findings"),
    idbAll<VaultRecord>("quarantine"),
    idbAll<AllowItem>("allow"),
    idbAll<LogItem>("log"),
    idbAll<{ id: string; settings?: Settings; trusted?: TrustedSender[] }>("meta"),
    idbAll<FolderItem>("folders"),
  ]);
  const settingsRow = meta.find((row) => row.id === "settings");
  const trustedRow = meta.find((row) => row.id === "trusted");
  for (const folder of folders) {
    if (folder.handle) rememberFolder(folder.id, folder.handle);
  }
  const freshFindings = findings.filter((item) => {
    if (item.reasonId.startsWith("zip-") || item.reasonId === "size" || item.reasonId === "ratio") return false;
    const storeApp = /(?:^|\/)apps\/(com\.google\.|com\.android\.|android\.|com\.samsung\.|com\.sec\.|com\.microsoft\.|com\.facebook\.|com\.instagram\.|com\.whatsapp|org\.telegram\.|com\.twitter\.|com\.spotify\.|com\.snapchat\.|com\.amazon\.|com\.huawei\.|com\.xiaomi\.|com\.miui\.|com\.oppo\.|com\.coloros\.|com\.heytap\.|com\.oplus\.|com\.oneplus\.|com\.vivo\.|com\.realme\.|com\.sony\.|com\.lge\.|com\.motorola\.)/.test(item.path);
    if (storeApp && (item.reasonId === "heuristic" || item.reasonId === "archive-depth")) return false;
    if (item.reasonId !== "heuristic") return true;
    const strong = ["overlay-accessibility", "sms-internet", "device-admin", "packer", "install-internet", "test-key"];
    return strong.some((id) => item.detail.includes(id));
  });
  if (freshFindings.length !== findings.length) {
    await Promise.all(findings.filter((item) => !freshFindings.includes(item)).map((item) => idbDelete("findings", item.id)));
  }
  patch({
    booted: true,
    findings: freshFindings.sort((a, b) => b.createdAt - a.createdAt),
    vault: vault
      .map(({ id, name, sha256, size, reasonId, createdAt }) => ({ id, name, sha256, size, reasonId, createdAt }))
      .sort((a, b) => b.createdAt - a.createdAt),
    allow,
    log: log.sort((a, b) => b.startedAt - a.startedAt).slice(0, 40),
    folders: folders.map(({ id, name }) => ({ id, name })),
    settings: { ...DEFAULT_SETTINGS, ...(settingsRow?.settings ?? {}) },
    trusted: trustedRow?.trusted ?? useKanaf.getState().trusted,
    integrity: readIntegrity(),
  });
  pushCallPolicy(useKanaf.getState().settings);
  await loadBundled();
  await drainNative();
  const loaded = useKanaf.getState().settings;
  if (!loaded.lastFeeds) await saveSettings({ ...loaded, lastFeeds: Date.now() });
  void maybeScheduled();
}

async function parseHashChunked(text: string, db: SignatureDb) {
  const lines = text.split("\n");
  const step = 5000;
  for (let i = 0; i < lines.length; i += step) {
    parseHashTsv(lines.slice(i, i + step).join("\n"), db);
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}
async function fetchText(url: string, onBytes?: (loaded: number, total: number) => void): Promise<string> {
  const response = await fetch(assetUrl(url));
  if (!response.ok || !response.body) throw new Error(String(response.status));
  const total = Number(response.headers.get("content-length") || 0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let loaded = 0;
  for (;;) {
    const step = await reader.read();
    if (step.done) break;
    chunks.push(step.value);
    loaded += step.value.byteLength;
    onBytes?.(loaded, total);
  }
  const blob = new Blob(chunks as BlobPart[]);
  return blob.text();
}

export async function loadBundled() {
  patch({ dbStatus: "loading", dbProgress: 0 });
  try {
    const manifest = (await (await fetch(assetUrl("/signatures/manifest.json"))).json()) as {
      builtAt: string;
      sources: SourceMeta[];
    };
    const db = emptyDb();
    db.builtAt = manifest.builtAt;
    db.sources = manifest.sources;
    const jobs: { url: string; apply: (text: string) => void | Promise<void>; weight: number }[] = [
      { url: "/signatures/hashes.tsv", apply: (text) => parseHashChunked(text, db), weight: 70 },
      {
        url: "/signatures/urls.txt",
        apply: (text) => {
          parseUrls(text, db);
        },
        weight: 18,
      },
      {
        url: "/signatures/hosts.txt",
        apply: (text) => {
          parseHosts(text, db);
        },
        weight: 8,
      },
      {
        url: "/signatures/certs.txt",
        apply: (text) => {
          parseCerts(text, db);
        },
        weight: 4,
      },
    ];
    let progress = 0;
    for (const job of jobs) {
      const text = await fetchText(job.url, (loaded, total) => {
        const inner = total ? loaded / total : 0;
        patch({ dbProgress: Math.round(progress + inner * job.weight) });
      });
      await job.apply(text);
      progress += job.weight;
      patch({ dbProgress: Math.round(progress) });
    }
    setDatabase(db);
    await applyStoredExtra(db);
    patch({
      dbStatus: "ready",
      dbProgress: 100,
      hashCount: db.hashRecords,
      sources: manifest.sources.map((source) => ({ ...source, state: source.count > 0 ? "ready" : "missing" })),
    });
  } catch (error) {
    patch({
      dbStatus: "error",
      notice: error instanceof Error ? error.message : "load",
    });
  }
}

function allowSet(): Set<string> {
  return new Set(useKanaf.getState().allow.map((item) => item.sha256));
}

async function addFindings(items: Omit<Finding, "id" | "createdAt">[], blobsFor: { idHint: string; bytes?: Uint8Array }[]) {
  const created: Finding[] = [];
  for (let i = 0; i < items.length; i++) {
    const finding: Finding = {
      ...items[i],
      id: crypto.randomUUID(),
      createdAt: Date.now(),
    };
    created.push(finding);
    await idbPut("findings", finding);
    const blob = blobsFor[i]?.bytes;
    if (blob) rememberBlob(finding.id, blob);
  }
  if (created.length === 0) return;
  patch({ findings: [...created, ...useKanaf.getState().findings], lastClean: false });
  void notifyWaiting(created.length);
}

async function notifyWaiting(count: number) {
  if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
  const note = new Notification("Kanaf", { body: String(count), tag: "kanaf-decision" });
  note.onclick = () => {
    window.focus();
    window.location.assign(assetUrl("/results"));
    note.close();
  };
}

export async function scanFiles(
  mode: "deep" | "quick" | "custom" | "scheduled" | "live",
  files: { name: string; path: string; bytes?: Uint8Array; url?: string; folderId?: string; segments?: string[]; packageName?: string; markers?: string[] }[],
) {
  if (useKanaf.getState().dbStatus !== "ready") return;
  if (useKanaf.getState().scan.running) return;
  resetCancel();
  const started = Date.now();
  const limits = mode === "quick" || mode === "scheduled" || mode === "live" ? QUICK_LIMITS : DEEP_LIMITS;
  let found = 0;
  let skipped = 0;
  const reports: CheckedFile[] = [];
  const noteSkip = (name: string) => {
    if (mode === "custom") reports.push({ name, size: 0, sha256: "", kind: "other", verdict: "skipped" });
  };
  patch({
    lastClean: false,
    notice: "",
    scan: { running: true, phase: "hash", mode, done: 0, total: files.length, current: "", found: 0, message: "" },
  });
  const db = getDatabase();
  const allow = allowSet();
  for (let i = 0; i < files.length; i++) {
    if (cancelled()) break;
    const file = files[i];
    patch({
      scan: { ...useKanaf.getState().scan, done: i, current: file.name, found },
    });
    let bytes = file.bytes;
    if (!bytes && file.url) {
      try {
        const response = await fetch(file.url);
        if (!response.ok) {
          skipped++;
          noteSkip(file.name);
          continue;
        }
        bytes = new Uint8Array(await response.arrayBuffer());
      } catch {
        skipped++;
        noteSkip(file.name);
        continue;
      }
    }
    if (!bytes) {
      skipped++;
      noteSkip(file.name);
      continue;
    }
    const cap = mode === "quick" || mode === "scheduled" || mode === "live" ? 64 * 1024 * 1024 : 48 * 1024 * 1024;
    if (bytes.byteLength > cap && !/\.(zip|apk|xapk|apks|jar)$/i.test(file.name)) {
      skipped++;
      noteSkip(file.name);
      continue;
    }
    if (bytes.byteLength > 96 * 1024 * 1024) {
      skipped++;
      noteSkip(file.name);
      continue;
    }
    try {
      const hits = await inspectBytes({
        name: file.name,
        path: file.path,
        bytes,
        db,
        allow,
        limits,
        markers: file.markers,
      });
      if (hits.length) {
        found += hits.length;
        if (mode === "live" && hits.some((hit) => hit.reasonId === "hash-match" || hit.reasonId === "eicar" || hit.reasonId === "bad-cert")) {
          kanafNative()?.note?.(file.name);
        }
        await addFindings(
          hits.map((hit) => ({
            kind: "file" as const,
            name: hit.name,
            path: hit.path,
            size: hit.size,
            sha256: hit.sha256,
            md5: hit.md5,
            verdict: hit.verdict,
            reasonId: hit.reasonId,
            detail: hit.detail,
            permissions: hit.permissions,
            folderId: file.folderId,
            segments: hit.path === file.path ? file.segments : undefined,
            packageName: hit.path === file.path ? file.packageName : undefined,
          })),
          hits.map((hit) => ({ idHint: hit.sha256, bytes: hit.path === file.path ? bytes : undefined })),
        );
      }
      if (mode === "custom") {
        const verdict = hits.some((hit) => hit.verdict === "malicious") ? "malicious" : hits.length ? "suspicious" : "clean";
        reports.push({
          name: file.name,
          size: bytes.byteLength,
          sha256: hits[0]?.sha256 || (await hashBuffer(bytes)).sha256,
          kind: classify(file.name, bytes),
          verdict,
        });
      }
    } catch {
      skipped++;
      noteSkip(file.name);
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  const status = cancelled() ? "cancelled" : "done";
  const entry: LogItem = {
    id: crypto.randomUUID(),
    mode,
    startedAt: started,
    finishedAt: Date.now(),
    files: files.length,
    findings: found,
    skipped,
    status,
  };
  await idbPut("log", entry);
  patch({
    log: [entry, ...useKanaf.getState().log].slice(0, 40),
    lastClean: status === "done" && found === 0,
    lastScan: { files: files.length, findings: found, skipped, downloads: useKanaf.getState().lastScan?.downloads ?? null },
    ...(mode === "custom" ? { checked: reports } : {}),
    scan: {
      running: false,
      phase: status === "cancelled" ? "cancelled" : "done",
      mode,
      done: files.length,
      total: files.length,
      current: "",
      found,
      message: "",
    },
  });
}

async function readHandleFile(handle: FileSystemFileHandle): Promise<Uint8Array> {
  const file = await handle.getFile();
  return new Uint8Array(await file.arrayBuffer());
}

async function walk(dir: FileSystemDirectoryHandle, prefix: string[]): Promise<{ name: string; path: string; segments: string[]; handle: FileSystemFileHandle }[]> {
  const out: { name: string; path: string; segments: string[]; handle: FileSystemFileHandle }[] = [];
  const listing = dir as FileSystemDirectoryHandle & {
    entries: () => AsyncIterable<[string, FileSystemHandle]>;
  };
  for await (const [name, handle] of listing.entries()) {
    if (cancelled()) break;
    if (handle.kind === "file") {
      out.push({
        name,
        path: [...prefix, name].join("/"),
        segments: [...prefix, name],
        handle: handle as FileSystemFileHandle,
      });
    } else {
      out.push(...(await walk(handle as FileSystemDirectoryHandle, [...prefix, name])));
    }
  }
  return out;
}

export async function scanDirectory(mode: "deep" | "quick" | "scheduled", handle: FileSystemDirectoryHandle, folderId: string) {
  if (useKanaf.getState().scan.running) return;
  resetCancel();
  patch({
    scan: { running: true, phase: "enum", mode, done: 0, total: 0, current: handle.name, found: 0, message: "" },
  });
  const listed = await walk(handle, []);
  const files = [];
  for (const item of listed) {
    if (cancelled()) break;
    const file = await item.handle.getFile();
    const limit = mode === "deep" ? 256 * 1024 * 1024 : 64 * 1024 * 1024;
    if (file.size > limit) continue;
    files.push({
      name: item.name,
      path: item.path,
      bytes: new Uint8Array(await file.arrayBuffer()),
      folderId,
      segments: item.segments,
    });
  }
  const stopped = cancelled();
  patch({ scan: { ...useKanaf.getState().scan, running: false, phase: "idle" } });
  if (stopped) return;
  await scanFiles(mode, files);
}

export function cancelScan() {
  requestCancel();
}

async function pickDirectory(startIn: string): Promise<FileSystemDirectoryHandle | "unsupported" | null> {
  const picker = window as PickerWindow;
  if (!picker.showDirectoryPicker) return "unsupported";
  try {
    return await picker.showDirectoryPicker({ mode: "readwrite", startIn });
  } catch {
    return null;
  }
}

async function filesFromInput(directory: boolean): Promise<{ name: string; path: string; bytes: Uint8Array }[]> {
  const input = document.createElement("input");
  input.type = "file";
  input.multiple = true;
  if (directory) input.setAttribute("webkitdirectory", "");
  const files = await new Promise<File[]>((resolve) => {
    input.onchange = () => resolve([...(input.files ?? [])]);
    input.click();
  });
  const payload = [];
  for (const file of files) {
    payload.push({
      name: file.name,
      path: file.webkitRelativePath || file.name,
      bytes: new Uint8Array(await file.arrayBuffer()),
    });
  }
  return payload;
}

export async function chooseFolder(mode: "deep" | "quick"): Promise<void> {
  const native = await filesFromNative("folder", mode);
  if (native !== "absent") {
    if (!native?.length) {
      patch({ notice: "grant" });
      return;
    }
    await scanFiles(
      mode,
      native.map((file) => ({ name: file.name, path: file.path || file.name, url: file.url })),
    );
    return;
  }
  const picked = await pickDirectory(mode === "quick" ? "downloads" : "documents");
  if (picked && picked !== "unsupported") {
    const id = crypto.randomUUID();
    rememberFolder(id, picked);
    await scanDirectory(mode, picked, id);
    return;
  }
  if (picked === null) {
    patch({ notice: "grant" });
    return;
  }
  const payload = await filesFromInput(true);
  if (!payload.length) {
    patch({ notice: "grant" });
    return;
  }
  await scanFiles(mode, payload);
}

export async function scanDevice(mode: "deep" | "quick"): Promise<void> {
  const native = kanafNative();
  if (!native?.listTargets) {
    await chooseFolder(mode);
    return;
  }
  let parsed: { files?: NativePick[]; downloads?: boolean };
  try {
    parsed = JSON.parse(native.listTargets(mode)) as { files?: NativePick[]; downloads?: boolean };
  } catch {
    patch({ notice: "nothing" });
    return;
  }
  const files = parsed.files ?? [];
  if (!files.length) {
    patch({ notice: "nothing" });
    return;
  }
  await maybeRefreshFeeds();
  patch({ lastScan: { files: 0, findings: 0, skipped: 0, downloads: parsed.downloads !== false } });
  await scanFiles(
    mode,
    files.map((file) => ({
      name: file.name,
      path: file.path || file.name,
      url: file.url,
      packageName: file.pkg,
      markers: file.perms,
    })),
  );
  if (parsed.downloads === false) {
    patch({
      lastScan: {
        ...(useKanaf.getState().lastScan ?? { files: files.length, findings: 0, skipped: 0, downloads: false }),
        downloads: false,
      },
    });
  }
}

export async function scanBehavior(): Promise<{ scanned: number; hits: number } | "web" | "fail"> {
  const native = kanafNative();
  if (!native?.listBehavior) return "web";
  let parsed: { scanned?: number; apps?: { name?: string; pkg?: string; path?: string; perms?: string[]; launcher?: boolean }[] };
  try {
    parsed = JSON.parse(native.listBehavior()) as typeof parsed;
  } catch {
    return "fail";
  }
  const apps = parsed.apps ?? [];
  const scanned = typeof parsed.scanned === "number" ? parsed.scanned : apps.length;
  let hits = 0;
  for (const app of apps) {
    const pkg = app.pkg || "";
    const path = app.path || `apps/${pkg}`;
    const markers = [...(app.perms ?? [])];
    if (app.launcher) markers.push("android.intent.category.LAUNCHER");
    const judged = scoreBehavior({ path, strings: markers });
    if (judged.band !== "suspicious") continue;
    hits++;
    const known = useKanaf.getState().findings.some((item) => item.path === path && item.reasonId === "heuristic");
    if (known) continue;
    const fingerprint = sha256Hex(new TextEncoder().encode(`behavior\n${path}`));
    await addFindings(
      [
        {
          kind: "file",
          name: app.name || pkg,
          path,
          size: 0,
          sha256: fingerprint,
          md5: "",
          verdict: "suspicious",
          reasonId: "heuristic",
          detail: judged.reasons.join(","),
          permissions: judged.permissions,
          packageName: pkg,
        },
      ],
      [{ idHint: fingerprint }],
    );
  }
  return { scanned, hits };
}

export async function readClipboard(): Promise<string> {
  const native = kanafNative();
  if (native?.clipboard) return native.clipboard();
  try {
    return await navigator.clipboard.readText();
  } catch {
    return "";
  }
}

export async function watchFolder(): Promise<boolean> {
  const picked = await pickDirectory("downloads");
  if (!picked || picked === "unsupported") return false;
  const id = crypto.randomUUID();
  rememberFolder(id, picked);
  const item: FolderItem = { id, name: picked.name, handle: picked };
  await idbPut("folders", item);
  patch({ folders: [...useKanaf.getState().folders, { id, name: picked.name }] });
  return true;
}

export async function removeFolder(id: string) {
  await idbDelete("folders", id);
  patch({ folders: useKanaf.getState().folders.filter((folder) => folder.id !== id) });
  if (useKanaf.getState().folders.length === 0) await setRealtime(false);
}

export async function chooseFiles(): Promise<"hit" | "clean" | "empty" | "busy"> {
  if (useKanaf.getState().scan.running || useKanaf.getState().dbStatus !== "ready") return "busy";
  const native = await filesFromNative("files", "custom");
  if (native !== "absent") {
    if (!native?.length) {
      patch({ notice: "nothing" });
      return "empty";
    }
    await scanFiles(
      "custom",
      native.map((file) => ({ name: file.name, path: file.path || file.name, url: file.url })),
    );
    return (useKanaf.getState().lastScan?.findings ?? 0) > 0 ? "hit" : "clean";
  }
  const picker = window as PickerWindow;
  if (picker.showOpenFilePicker) {
    try {
      const handles = await picker.showOpenFilePicker({ multiple: true, mode: "readwrite" });
      const files = [];
      for (const handle of handles) {
        const file = await handle.getFile();
        files.push({ name: file.name, path: file.name, bytes: new Uint8Array(await file.arrayBuffer()) });
      }
      if (!files.length) return "empty";
      await scanFiles("custom", files);
      return (useKanaf.getState().lastScan?.findings ?? 0) > 0 ? "hit" : "clean";
    } catch {
      return "empty";
    }
  }
  const input = document.createElement("input");
  input.type = "file";
  input.multiple = true;
  const files = await new Promise<File[]>((resolve) => {
    input.onchange = () => resolve([...(input.files ?? [])]);
    input.click();
  });
  const payload = [];
  for (const file of files) payload.push({ name: file.name, path: file.name, bytes: new Uint8Array(await file.arrayBuffer()) });
  if (!payload.length) {
    patch({ notice: "nothing" });
    return "empty";
  }
  await scanFiles("custom", payload);
  return (useKanaf.getState().lastScan?.findings ?? 0) > 0 ? "hit" : "clean";
}

export async function allowFinding(id: string) {
  const finding = useKanaf.getState().findings.find((item) => item.id === id);
  if (!finding) return;
  const row: AllowItem = { id: finding.sha256 || finding.id, sha256: finding.sha256 || finding.id, name: finding.name, createdAt: Date.now() };
  await idbPut("allow", row);
  await idbDelete("findings", id);
  dropBlob(id);
  patch({
    allow: [row, ...useKanaf.getState().allow.filter((item) => item.sha256 !== row.sha256)],
    findings: useKanaf.getState().findings.filter((item) => item.id !== id),
    notice: "allowed",
  });
}

export async function revokeAllow(id: string) {
  await idbDelete("allow", id);
  patch({ allow: useKanaf.getState().allow.filter((item) => item.id !== id) });
}

export async function quarantineFinding(id: string): Promise<"moved" | "copied" | "missing"> {
  const finding = useKanaf.getState().findings.find((item) => item.id === id);
  const bytes = takeBlob(id);
  if (!finding || !bytes) return "missing";
  await seal(bytes, {
    id: crypto.randomUUID(),
    name: finding.name,
    sha256: finding.sha256,
    size: bytes.byteLength,
    reasonId: finding.reasonId,
    createdAt: Date.now(),
  });
  const removed = await deleteOriginal(finding);
  await idbDelete("findings", id);
  dropBlob(id);
  const vault = await idbAll<VaultRecord>("quarantine");
  patch({
    findings: useKanaf.getState().findings.filter((item) => item.id !== id),
    vault: vault.map(({ id: vid, name, sha256, size, reasonId, createdAt }) => ({ id: vid, name, sha256, size, reasonId, createdAt })),
    notice: removed ? "moved" : "remains",
  });
  return removed ? "moved" : "copied";
}

async function deleteOriginal(finding: Finding): Promise<boolean> {
  if (!finding.folderId || !finding.segments?.length) return false;
  const root = folderHandle(finding.folderId);
  if (!root) return false;
  try {
    let dir = root;
    for (let i = 0; i < finding.segments.length - 1; i++) dir = await dir.getDirectoryHandle(finding.segments[i]);
    await dir.removeEntry(finding.segments[finding.segments.length - 1]);
    return true;
  } catch {
    return false;
  }
}

export async function deleteFinding(id: string): Promise<boolean> {
  const finding = useKanaf.getState().findings.find((item) => item.id === id);
  if (!finding) return false;
  if (finding.packageName && kanafNative()?.uninstall) {
    kanafNative()?.uninstall?.(finding.packageName);
    patch({ notice: "uninstall" });
    return false;
  }
  const removed = await deleteOriginal(finding);
  if (!removed) {
    patch({ notice: "delete-blocked" });
    return false;
  }
  await idbDelete("findings", id);
  dropBlob(id);
  patch({ findings: useKanaf.getState().findings.filter((item) => item.id !== id), notice: "deleted" });
  return true;
}

export async function restoreVault(id: string) {
  const rows = await idbAll<VaultRecord>("quarantine");
  const row = rows.find((item) => item.id === id);
  if (!row) return;
  const bytes = await openVault(row);
  const blob = new Blob([bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer]);
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = row.name;
  link.click();
  URL.revokeObjectURL(url);
}

export async function purgeVault(id: string) {
  await destroyVault(id);
  patch({ vault: useKanaf.getState().vault.filter((item) => item.id !== id) });
}

export async function scanLink(raw: string) {
  const db = getDatabase();
  const verdict = analyzeUrl(raw, db);
  return verdict;
}

export async function rememberUrl(raw: string) {
  const norm = normalizeUrl(raw);
  if (!norm) return;
  const row: AllowItem = { id: norm.href, sha256: norm.href, name: norm.href, createdAt: Date.now() };
  await idbPut("allow", row);
  patch({ allow: [row, ...useKanaf.getState().allow] });
}

export function inspectMessage(sender: string, text: string) {
  const db = getDatabase();
  const trusted = useKanaf.getState().trusted;
  const official = useKanaf.getState().settings.officialNumbers.map((row) => row.e164);
  const result = analyzeMessage({ sender, text, trusted, official, db: { hosts: db.hosts, urls: db.urls } });
  const fingerprint = sha256Hex(new TextEncoder().encode(`${sender}\n${text}`));
  return { ...result, fingerprint };
}

type InboxFile = { name?: string; url?: string };
type InboxMessage = { from?: string; body?: string; files?: InboxFile[] };

export type InboxHit = {
  from: string;
  verdict: "malicious" | "suspicious";
  reasons: string[];
  detail: string;
  excerpt: string;
  file?: string;
};

export async function scanInbox(onProgress?: (done: number, total: number) => void): Promise<{
  status: "ok" | "denied" | "web" | "empty";
  scanned: number;
  hits: InboxHit[];
}> {
  const native = kanafNative();
  if (!native?.listMessages) return { status: "web", scanned: 0, hits: [] };
  let parsed = readInbox(native.listMessages());
  if (parsed.status === "need") {
    const ok = await askSms();
    if (!ok) return { status: "denied", scanned: 0, hits: [] };
    parsed = readInbox(native.listMessages());
  }
  if (parsed.status !== "ok") return { status: parsed.status === "denied" ? "denied" : "empty", scanned: 0, hits: [] };
  const messages = parsed.messages ?? [];
  if (!messages.length) return { status: "empty", scanned: 0, hits: [] };
  const hits: InboxHit[] = [];
  const db = getDatabase();
  const allow = allowSet();
  for (let i = 0; i < messages.length; i++) {
    onProgress?.(i, messages.length);
    const message = messages[i];
    const from = message?.from || "";
    const body = message?.body || "";
    if (body) {
      const result = inspectMessage(from, body);
      if (result.verdict !== "clean") {
        const detail = result.clause || result.urls.find((url) => url.hint)?.hint || result.urls.find((url) => url.verdict !== "clean")?.host || result.phones.find((phone) => phone.verdict !== "clean")?.e164 || result.reasons[0] || "";
        hits.push({ from, verdict: result.verdict, reasons: result.reasons, detail, excerpt: body.slice(0, 180) });
        if (!useKanaf.getState().findings.some((item) => item.sha256 === result.fingerprint)) {
          await keepMessageFinding(from, result.fingerprint, result.reasons[0] || "listed", detail, result.verdict);
        }
      }
    }
    for (const file of message?.files ?? []) {
      if (!file?.url || !file.name) continue;
      try {
        const response = await fetch(file.url);
        if (!response.ok) continue;
        const bytes = new Uint8Array(await response.arrayBuffer());
        const found = await inspectBytes({
          name: file.name,
          path: `mms/${from}/${file.name}`,
          bytes,
          db,
          allow,
          limits: QUICK_LIMITS,
        });
        for (const hit of found) {
          hits.push({
            from,
            verdict: hit.verdict,
            reasons: [hit.reasonId],
            detail: hit.detail || file.name,
            excerpt: body.slice(0, 180),
            file: file.name,
          });
          const known = useKanaf.getState().findings.some((item) => item.sha256 === hit.sha256 && item.reasonId === hit.reasonId);
          if (!known) {
            await addFindings(
              [
                {
                  kind: "file",
                  name: file.name,
                  path: `mms/${from}/${file.name}`,
                  size: hit.size,
                  sha256: hit.sha256,
                  md5: hit.md5,
                  verdict: hit.verdict,
                  reasonId: hit.reasonId,
                  detail: hit.detail,
                  permissions: hit.permissions,
                },
              ],
              [{ idHint: hit.sha256, bytes: bytes.byteLength <= 8 * 1024 * 1024 ? bytes : undefined }],
            );
          }
        }
      } catch {
        /* attachment unreadable */
      }
    }
  }
  onProgress?.(messages.length, messages.length);
  return { status: "ok", scanned: messages.length, hits };
}

function readInbox(raw: string): { status: string; messages?: InboxMessage[] } {
  try {
    const parsed = JSON.parse(raw) as { status?: string; messages?: InboxMessage[] };
    return { status: parsed.status || "empty", messages: parsed.messages };
  } catch {
    return { status: "denied" };
  }
}

async function askSms(): Promise<boolean> {
  const native = kanafNative();
  if (!native?.askSms) return false;
  return new Promise((resolve) => {
    const timer = window.setTimeout(() => {
      permWait = null;
      resolve(false);
    }, 30000);
    permWait = (ok) => {
      window.clearTimeout(timer);
      resolve(ok);
    };
    native.askSms!();
  });
}

export async function keepMessageFinding(sender: string, fingerprint: string, reasonId: string, detail: string, verdict: Finding["verdict"]) {
  await addFindings(
    [
      {
        kind: "message",
        name: sender || fingerprint.slice(0, 12),
        path: fingerprint,
        size: 0,
        sha256: fingerprint,
        md5: "",
        verdict,
        reasonId,
        detail,
        permissions: [],
        sender,
      },
    ],
    [],
  );
}

export async function runEicar() {
  const bytes = eicarBytes();
  await scanFiles("custom", [{ name: "eicar.com", path: "eicar.com", bytes }]);
  return useKanaf.getState().findings.some((item) => item.reasonId === "eicar");
}

export async function saveSettings(settings: Settings) {
  const next = { ...DEFAULT_SETTINGS, ...settings, officialNumbers: settings.officialNumbers ?? [], blockedNumbers: settings.blockedNumbers ?? [] };
  patch({ settings: next });
  pushCallPolicy(next);
  await idbPut("meta", { id: "settings", settings: next });
}

function pushCallPolicy(settings: Settings) {
  kanafNative()?.setCallPolicy?.(
    JSON.stringify({
      official: settings.officialNumbers.map((row) => row.e164),
      blocked: settings.blockedNumbers,
    }),
  );
}

export function exportDecisions(): string {
  const { findings, log } = useKanaf.getState();
  const lines = ["Kanaf decisions", new Date().toISOString(), ""];
  for (const entry of log) {
    lines.push(`scan ${entry.mode} ${entry.status} files=${entry.files} findings=${entry.findings}`);
  }
  lines.push("");
  for (const item of findings) {
    lines.push(`${item.verdict}\t${item.reasonId}\t${item.name}\t${item.detail}`);
  }
  return lines.join("\n");
}

export async function saveDecisions(): Promise<"ok" | "empty" | "web" | "fail"> {
  const text = exportDecisions();
  if (!useKanaf.getState().findings.length && !useKanaf.getState().log.length) return "empty";
  const native = kanafNative();
  if (native?.saveText) return native.saveText("kanaf-decisions.txt", text) === "ok" ? "ok" : "fail";
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "kanaf-decisions.txt";
  link.click();
  URL.revokeObjectURL(url);
  return "web";
}

export async function saveTrusted(trusted: TrustedSender[]) {
  patch({ trusted });
  await idbPut("meta", { id: "trusted", trusted });
}

export async function setRealtime(on: boolean): Promise<string> {
  const native = kanafNative();
  if (native?.setWatch) {
    if (!on) {
      native.setWatch(false);
      patch({ realtime: false, realtimeNote: "off" });
      return "off";
    }
    const allowed = await askNativeNotify();
    if (!allowed) {
      native.setWatch(false);
      patch({ realtime: false, realtimeNote: "need" });
      return "need";
    }
    const started = native.setWatch(true);
    if (started === "fail") {
      patch({ realtime: false, realtimeNote: "fail" });
      return "fail";
    }
    patch({ realtime: true, realtimeNote: "watching" });
    return "watching";
  }
  if (!on) {
    observer?.disconnect();
    observer = null;
    patch({ realtime: false, realtimeNote: "off" });
    return "off";
  }
  if (typeof Notification !== "undefined" && Notification.permission !== "granted") {
    const permission = await Notification.requestPermission();
    if (permission !== "granted") {
      patch({ realtime: false, realtimeNote: "need" });
      return "need";
    }
  }
  const picker = window as PickerWindow;
  if (!picker.FileSystemObserver) {
    patch({ realtime: false, realtimeNote: "missing" });
    return "missing";
  }
  let folder = useKanaf.getState().folders[0];
  if (!folder) {
    const ok = await watchFolder();
    if (!ok) {
      patch({ realtime: false, realtimeNote: "pick" });
      return "pick";
    }
    folder = useKanaf.getState().folders[0];
  }
  const handle = folder ? folderHandle(folder.id) : undefined;
  if (!handle || !folder) {
    patch({ realtime: false, realtimeNote: "missing" });
    return "missing";
  }
  const live = new picker.FileSystemObserver((records) => {
    for (const record of records) {
      const changed = record.changedHandle;
      if (changed && changed.kind === "file") {
        void readHandleFile(changed as FileSystemFileHandle).then((bytes) =>
          scanFiles("live", [{ name: changed.name, path: changed.name, bytes, folderId: folder?.id, segments: [changed.name] }]),
        );
      }
    }
  });
  await live.observe(handle, { recursive: true });
  observer = live;
  patch({ realtime: true, realtimeNote: "watching" });
  return "watching";
}

async function askNativeNotify(): Promise<boolean> {
  const native = kanafNative();
  if (!native || typeof native.askNotify !== "function") return true;
  return new Promise((resolve) => {
    const timer = window.setTimeout(() => {
      permWait = null;
      resolve(false);
    }, 20000);
    permWait = (ok) => {
      window.clearTimeout(timer);
      resolve(ok);
    };
    native.askNotify!();
  });
}

async function charging(): Promise<boolean> {
  const batteryApi = navigator as Navigator & { getBattery?: () => Promise<{ charging: boolean }> };
  if (!batteryApi.getBattery) return true;
  try {
    const battery = await batteryApi.getBattery();
    return battery.charging;
  } catch {
    return true;
  }
}

async function maybeScheduled() {
  const { settings, folders, scan } = useKanaf.getState();
  if (!settings.scheduleEnabled || scan.running || folders.length === 0) return;
  const span = settings.every === "week" ? 7 * 86400000 : 86400000;
  if (Date.now() - settings.lastScheduled < span) return;
  if (settings.chargingOnly && !(await charging())) {
    patch({ notice: "charging" });
    return;
  }
  if (kanafNative()?.listTargets) {
    await saveSettings({ ...settings, lastScheduled: Date.now() });
    await scanDevice("quick");
    return;
  }
  const folder = folders[0];
  const handle = folderHandle(folder.id);
  if (!handle) return;
  await saveSettings({ ...settings, lastScheduled: Date.now() });
  await scanDirectory("scheduled", handle, folder.id);
}

export function metered(): boolean | null {
  const native = kanafNative();
  if (native?.network) {
    const kind = native.network();
    if (kind === "cellular") return true;
    if (kind === "wifi" || kind === "ethernet") return false;
    if (kind === "none") return false;
  }
  const connection = (navigator as Navigator & { connection?: { type?: string; saveData?: boolean } }).connection;
  if (!connection) return null;
  if (connection.saveData) return true;
  if (connection.type === "cellular") return true;
  if (connection.type === "wifi" || connection.type === "ethernet") return false;
  return null;
}

export function networkKind(): "wifi" | "cellular" | "none" | "unknown" {
  const native = kanafNative();
  if (native?.network) {
    const kind = native.network();
    if (kind === "wifi" || kind === "ethernet") return "wifi";
    if (kind === "cellular") return "cellular";
    if (kind === "none") return "none";
  }
  const meteredNow = metered();
  if (meteredNow === true) return "cellular";
  if (meteredNow === false) return "wifi";
  return "unknown";
}

export function openDeviceSettings(kind: string) {
  kanafNative()?.openSettings?.(kind);
}

async function pullNative(url: string): Promise<Uint8Array> {
  const native = kanafNative();
  if (!native || typeof native.fetchUrl !== "function") throw new Error("download unavailable");
  const id = crypto.randomUUID();
  const ok = await new Promise<boolean>((resolve) => {
    const timer = window.setTimeout(() => {
      netWait = null;
      resolve(false);
    }, 180000);
    const previous = netWait;
    netWait = (got, success) => {
      if (got !== id) {
        previous?.(got, success);
        return;
      }
      window.clearTimeout(timer);
      netWait = null;
      resolve(success);
    };
    netStatus = "";
    native.fetchUrl!(id, url);
  });
  if (!ok) throw new Error(netStatus || "download failed");
  const response = await fetch(`https://appassets.androidplatform.net/__net/${encodeURIComponent(id)}`);
  if (!response.ok) throw new Error("download missing");
  return new Uint8Array(await response.arrayBuffer());
}

function textOf(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

const FEED_PARTS = ["urlhaus", "malwarebazaar", "cscb", "clamav-daily", "threatfox", "feodo", "openphish", "et-open"] as const;

function freshHashLines(text: string, db: SignatureDb): string[] {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (!line) continue;
    const [kind, hash] = line.split("\t");
    if (kind !== "md5" && kind !== "sha1" && kind !== "sha256") continue;
    if (!hash) continue;
    if (db.hashes.has(`${kind}:${hash.toLowerCase()}`)) continue;
    out.push(line);
  }
  return out;
}

function keepHashes(text: string, db: SignatureDb, sink: string[]): number {
  const fresh = freshHashLines(text, db);
  sink.push(...fresh);
  return parseHashTsv(fresh.join("\n"), db);
}

function keepUrls(text: string, db: SignatureDb, sink: string[]): number {
  const fresh: string[] = [];
  for (const line of text.split("\n")) {
    const url = line.trim();
    if (!url || url.startsWith("#") || db.urls.has(url)) continue;
    fresh.push(url);
  }
  sink.push(...fresh.map((url) => `U ${url}`));
  return parseUrls(fresh.join("\n"), db);
}

function keepHosts(text: string, db: SignatureDb, sink: string[]): number {
  const fresh: string[] = [];
  for (const line of text.split("\n")) {
    const host = line.trim().toLowerCase();
    if (!host || host.startsWith("#") || db.hosts.has(host)) continue;
    fresh.push(host);
  }
  sink.push(...fresh.map((host) => `H ${host}`));
  return parseHosts(fresh.join("\n"), db);
}

function keepCerts(text: string, db: SignatureDb, sink: string[]): number {
  const fresh: string[] = [];
  for (const line of text.split("\n")) {
    const thumb = line.split("\t")[0] ?? "";
    if (!/^[0-9a-f]{64}$/.test(thumb) || db.certs.has(thumb)) continue;
    fresh.push(line);
  }
  sink.push(...fresh.map((line) => `C ${line}`));
  return parseCerts(fresh.join("\n"), db);
}

function keepFeed(text: string, db: SignatureDb, sink: string[]): number {
  const urls: string[] = [];
  const hosts: string[] = [];
  const hashes: string[] = [];
  for (const line of text.split("\n")) {
    if (line.startsWith("U ")) urls.push(line.slice(2).trim());
    else if (line.startsWith("H ")) hosts.push(line.slice(2).trim());
    else if (/^(md5|sha1|sha256)\t/.test(line)) hashes.push(line);
  }
  return keepUrls(urls.join("\n"), db, sink) + keepHosts(hosts.join("\n"), db, sink) + keepHashes(hashes.join("\n"), db, sink);
}

async function readFeedExtra(): Promise<string> {
  const rows = await idbAll<{ id: string; body?: string }>("meta");
  return rows.find((row) => row.id === "feed-extra")?.body ?? "";
}

async function applyStoredExtra(db: SignatureDb): Promise<void> {
  let body = "";
  try {
    body = await readFeedExtra();
  } catch {
    return;
  }
  if (!body) return;
  const hashes: string[] = [];
  const urls: string[] = [];
  const hosts: string[] = [];
  const certs: string[] = [];
  for (const line of body.split("\n")) {
    if (line.startsWith("U ")) urls.push(line.slice(2));
    else if (line.startsWith("H ")) hosts.push(line.slice(2));
    else if (line.startsWith("C ")) certs.push(line.slice(2));
    else if (line) hashes.push(line);
  }
  if (hashes.length) parseHashTsv(hashes.join("\n"), db);
  if (urls.length) parseUrls(urls.join("\n"), db);
  if (hosts.length) parseHosts(hosts.join("\n"), db);
  if (certs.length) parseCerts(certs.join("\n"), db);
}

async function saveFeedExtra(chunk: string): Promise<void> {
  const trimmed = chunk.trim();
  if (!trimmed) return;
  const merged = new Set<string>();
  const prev = await readFeedExtra();
  if (prev) {
    for (const line of prev.split("\n")) if (line) merged.add(line);
  }
  for (const line of trimmed.split("\n")) if (line) merged.add(line);
  await idbPut("meta", { id: "feed-extra", body: [...merged].join("\n") });
}

function ingestExtra(part: string, raw: string): string {
  if (part === "threatfox") return threatFoxToFeed(raw);
  if (part === "feodo" || part === "et-open") return ipsToFeed(raw);
  if (part === "openphish") return urlsToFeed(raw);
  return "";
}

async function refreshOnDevice(): Promise<void> {
  const parts = FEED_PARTS;
  const db = getDatabase();
  const failedIds: string[] = [];
  const extra: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    patch({
      dbProgress: Math.round((i / parts.length) * 100),
      sources: useKanaf.getState().sources.map((source) => (source.id === part ? { ...source, state: "loading", error: undefined } : source)),
    });
    try {
      let added = 0;
      if (part === "urlhaus") {
        const raw = textOf(await pullNative("https://urlhaus.abuse.ch/downloads/text/"));
        const lines: string[] = [];
        const hosts: string[] = [];
        for (const line of raw.split("\n")) {
          const norm = normalizeUrl(line);
          if (!norm) continue;
          lines.push(norm.href);
          hosts.push(norm.hostname);
        }
        added = keepUrls(lines.join("\n"), db, extra);
        keepHosts(hosts.join("\n"), db, extra);
      } else if (part === "malwarebazaar") {
        const sha = await pullNative("https://bazaar.abuse.ch/export/txt/sha256/recent/");
        const md5 = await pullNative("https://bazaar.abuse.ch/export/txt/md5/recent/");
        const rows: string[] = [];
        for (const line of textOf(sha).split("\n")) {
          const hash = line.trim().toLowerCase();
          if (/^[0-9a-f]{64}$/.test(hash)) rows.push(`sha256\t${hash}\t*\tmalwarebazaar\tMalwareBazaar-recent`);
        }
        for (const line of textOf(md5).split("\n")) {
          const hash = line.trim().toLowerCase();
          if (/^[0-9a-f]{32}$/.test(hash)) rows.push(`md5\t${hash}\t*\tmalwarebazaar\tMalwareBazaar-recent`);
        }
        added = keepHashes(rows.join("\n"), db, extra);
      } else if (part === "cscb") {
        const raw = textOf(await pullNative("https://bazaar.abuse.ch/export/csv/cscb/"));
        const rows: string[] = [];
        for (const line of raw.split("\n")) {
          if (!line || line.startsWith("#") || line.startsWith('"time')) continue;
          const cols = line.split(",");
          const thumb = (cols[2] || "").replaceAll('"', "").trim().toLowerCase();
          const reason = (cols[8] || "CSCB").replaceAll('"', "").trim();
          if (/^[0-9a-f]{64}$/.test(thumb)) rows.push(`${thumb}\t${reason}`);
        }
        added = keepCerts(rows.join("\n"), db, extra);
      } else if (part === "threatfox" || part === "feodo" || part === "openphish" || part === "et-open") {
        const remote =
          part === "threatfox"
            ? "https://threatfox.abuse.ch/export/csv/recent/"
            : part === "feodo"
              ? "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
              : part === "openphish"
                ? "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
                : "https://rules.emergingthreats.net/blockrules/compromised-ips.txt";
        added = keepFeed(ingestExtra(part, textOf(await pullNative(remote))), db, extra);
      } else {
        let parsed: Awaited<ReturnType<typeof parseCvd>> | null = null;
        let last = "unavailable";
        for (const url of ["https://database.clamav.net/daily.cvd", "https://packages.microsoft.com/clamav/daily.cvd"]) {
          try {
            parsed = await parseCvd(await pullNative(url));
            break;
          } catch (error) {
            last = error instanceof Error ? error.message : "cvd";
          }
        }
        if (!parsed) throw new Error(last);
        const rows = parsed.records.map(
          (record) => `${record.kind}\t${record.hash}\t${record.size ?? "*"}\tclamav-daily\t${record.name.replaceAll("\t", " ")}`,
        );
        added = keepHashes(rows.join("\n"), db, extra);
      }
      patch({
        sources: useKanaf.getState().sources.map((source) =>
          source.id === part ? { ...source, state: "ready", count: added || source.count, updatedAt: new Date().toISOString(), error: undefined } : source,
        ),
      });
    } catch (error) {
      const why = error instanceof Error && error.message ? error.message.slice(0, 40) : "";
      failedIds.push(why ? `${part} ${why}` : part);
      patch({
        sources: useKanaf.getState().sources.map((source) =>
          source.id === part ? { ...source, state: "failed", error: error instanceof Error ? error.message : "failed" } : source,
        ),
      });
    }
  }
  setDatabase(db);
  try {
    await saveFeedExtra(extra.join("\n"));
  } catch {
    /* the count stays for this session even if the save fails */
  }
  patch({ hashCount: db.hashRecords, dbProgress: 100, notice: failedIds.length ? "" : "update-ok" });
  if (!failedIds.length) await saveSettings({ ...useKanaf.getState().settings, lastFeeds: Date.now() });
}

export async function refreshSources(forceCellular: boolean): Promise<void> {
  const { settings, dbStatus, integrity } = useKanaf.getState();
  if (dbStatus !== "ready") return;
  if (integrity === "repacked") {
    patch({ notice: "repacked" });
    return;
  }
  if (settings.wifiOnly && !forceCellular && metered() === true) {
    patch({ notice: "cellular" });
    return;
  }
  if (kanafNative()?.fetchUrl) {
    await refreshOnDevice();
    return;
  }
  const parts = FEED_PARTS;
  const db: SignatureDb = getDatabase();
  const failedIds: string[] = [];
  const extra: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    patch({
      dbProgress: Math.round((i / parts.length) * 100),
      sources: useKanaf.getState().sources.map((source) => (source.id === part || (part === "urlhaus" && source.id === "urlhaus") ? { ...source, state: "loading" } : source)),
    });
    try {
      const response = await fetch(assetUrl(`/api/signatures?part=${part}`));
      if (!response.ok) throw new Error(await response.text());
      const text = await response.text();
      if (part === "urlhaus") {
        const hosts: string[] = [];
        for (const line of text.split("\n")) {
          try {
            hosts.push(new URL(line.trim()).hostname);
          } catch {
            /* skip malformed rows */
          }
        }
        keepUrls(text, db, extra);
        keepHosts(hosts.join("\n"), db, extra);
      } else if (part === "cscb") {
        keepCerts(text, db, extra);
      } else if (part === "threatfox" || part === "feodo" || part === "openphish" || part === "et-open") {
        keepFeed(text, db, extra);
      } else {
        keepHashes(text, db, extra);
      }
      patch({
        sources: useKanaf.getState().sources.map((source) =>
          source.id === part ? { ...source, state: "ready", updatedAt: new Date().toISOString(), error: undefined } : source,
        ),
      });
    } catch (error) {
      const why = error instanceof Error && error.message ? error.message.slice(0, 40) : "";
      failedIds.push(why ? `${part} ${why}` : part);
      patch({
        sources: useKanaf.getState().sources.map((source) =>
          source.id === part ? { ...source, state: "failed", error: error instanceof Error ? error.message : "failed" } : source,
        ),
      });
    }
  }
  setDatabase(db);
  try {
    await saveFeedExtra(extra.join("\n"));
  } catch {
    /* the count stays for this session even if the save fails */
  }
  patch({ hashCount: db.hashRecords, dbProgress: 100, notice: failedIds.length ? "" : "update-ok" });
  if (!failedIds.length) await saveSettings({ ...useKanaf.getState().settings, lastFeeds: Date.now() });
}

export async function askCloud(text: string, key: string): Promise<{ verdict: "suspicious" | "clean"; clause: string } | "need" | "fail"> {
  const secret = key.trim();
  if (!secret) return "need";
  const body = text.trim().slice(0, 2000);
  if (!body) return "fail";
  try {
    const response = await fetch("https://api.x.ai/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${secret}` },
      body: JSON.stringify({
        model: "grok-3-mini",
        temperature: 0,
        messages: [
          {
            role: "system",
            content: "Judge one pasted message for phishing. Reply with two lines only.\nVERDICT: suspicious or clean\nSENTENCE: the short clause you relied on, or -",
          },
          { role: "user", content: body },
        ],
      }),
    });
    if (!response.ok) return "fail";
    const json = (await response.json()) as { choices?: { message?: { content?: string } }[] };
    const content = json.choices?.[0]?.message?.content || "";
    const line = content.match(/VERDICT:\s*(suspicious|clean)/i)?.[1]?.toLowerCase();
    const sentence = content.match(/SENTENCE:\s*(.+)/i)?.[1]?.trim() || "";
    return { verdict: line === "suspicious" ? "suspicious" : "clean", clause: sentence === "-" ? "" : sentence.slice(0, 180) };
  } catch {
    return "fail";
  }
}

export async function tryRedirect(raw: string): Promise<{ ok: boolean; final?: string }> {
  const norm = normalizeUrl(raw);
  if (!norm) return { ok: false };
  try {
    const response = await fetch(norm.href, { method: "GET", redirect: "follow" });
    return { ok: true, final: response.url || norm.href };
  } catch {
    return { ok: false };
  }
}
