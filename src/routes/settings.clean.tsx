import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Frame, TopBar } from "@/components/kanaf/chrome";
import { useI18n } from "@/lib/kanaf/i18n";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/settings/clean")({ component: Clean });

type Junk = { id: string; name: string; size: number; kind?: string };
type AppRow = { pkg: string; name: string };

function bridge() {
  return (window as Window & {
    KanafNative?: {
      clearOwnCache?: () => string;
      listJunk?: () => string;
      deleteJunk?: (json: string) => string;
      askClearAppCache?: () => string;
      listUserApps?: () => string;
      openAppInfo?: (pkg: string) => void;
      filesAccess?: () => string;
      askFilesAccess?: () => void;
    };
  }).KanafNative;
}

function sizeLabel(size: number): string {
  if (!Number.isFinite(size) || size < 0) return "";
  if (size >= 1_000_000_000) return `${(size / 1_000_000_000).toFixed(1)} GB`;
  if (size >= 1_000_000) return `${Math.round(size / 1_000_000)} MB`;
  if (size >= 1_000) return `${Math.round(size / 1_000)} KB`;
  return `${size} B`;
}

function Clean() {
  const { t } = useI18n();
  const shell = useKanaf((s) => s.shell);
  const [note, setNote] = useState("");
  const [rows, setRows] = useState<Junk[]>([]);
  const [apps, setApps] = useState<AppRow[]>([]);

  return (
    <Frame>
      <TopBar title={t.cleanTitle} />
      <p className="mb-3 text-sm leading-relaxed text-muted">{t.cleanLead}</p>
      {shell !== "android" ? <p className="mb-3 text-sm text-muted">{t.cleanWeb}</p> : null}
      <div className="flex flex-col gap-2">
        <button
          type="button"
          className="h-11 w-full rounded-xl bg-teal text-sm font-semibold text-teal-ink"
          onClick={() => {
            const native = bridge();
            if (!native?.askClearAppCache || shell !== "android") {
              setNote(t.cleanWeb);
              return;
            }
            const result = native.askClearAppCache();
            if (result === "ok") {
              setApps([]);
              setNote(t.cleanAppsNote);
              return;
            }
            try {
              const parsed = JSON.parse(native.listUserApps?.() || "[]") as AppRow[];
              setApps(Array.isArray(parsed) ? parsed : []);
            } catch {
              setApps([]);
            }
            setNote(t.cleanAppsFail);
          }}
        >
          {t.cleanApps}
        </button>
        <button
          type="button"
          className="h-11 w-full rounded-xl border border-line bg-ink-2 text-sm font-medium"
          onClick={() => {
            const native = bridge();
            if (!native?.clearOwnCache || shell !== "android") {
              setNote(t.cleanWeb);
              return;
            }
            native.clearOwnCache();
            setApps([]);
            if (native.filesAccess?.() === "need") {
              native.askFilesAccess?.();
              setRows([]);
              setNote(t.cleanNeedFiles);
              return;
            }
            try {
              const parsed = JSON.parse(native.listJunk?.() || "[]") as Junk[];
              setRows(Array.isArray(parsed) ? parsed : []);
              setNote(parsed.length ? t.cleanFreed : `${t.cleanFreed} ${t.cleanNone}`);
            } catch {
              setRows([]);
              setNote(t.cleanFreed);
            }
          }}
        >
          {t.cleanTemp}
        </button>
      </div>
      {note ? <p className="mt-3 text-sm text-teal">{note}</p> : null}
      <ul className="mt-3 space-y-2">
        {apps.map((app) => (
          <li key={app.pkg} className="glass flex items-center gap-2 p-3 text-sm">
            <span className="min-w-0 flex-1 truncate" dir="auto">
              {app.name}
            </span>
            <button type="button" className="text-gold" onClick={() => bridge()?.openAppInfo?.(app.pkg)}>
              {t.cleanOpen}
            </button>
          </li>
        ))}
        {rows.map((row) => (
          <li key={row.id} className="glass flex items-center gap-2 p-3 text-sm">
            <span className="min-w-0 flex-1" dir="ltr">
              <span className="block truncate text-left">{row.name}</span>
              <span className="mt-0.5 block text-left text-xs text-muted">{sizeLabel(row.size)}</span>
            </span>
            <button
              type="button"
              className="text-gold"
              onClick={() => {
                bridge()?.deleteJunk?.(JSON.stringify([row.id]));
                setRows((current) => current.filter((item) => item.id !== row.id));
              }}
            >
              {t.cleanDelete}
            </button>
          </li>
        ))}
      </ul>
    </Frame>
  );
}
