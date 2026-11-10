import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { Frame, HomeBar, Notice } from "@/components/kanaf/chrome";
import { resultsLabel, scanSummary, useI18n } from "@/lib/kanaf/i18n";
import { cancelScan, chooseFiles, chooseFolder, metered, refreshSources, scanDevice, setRealtime } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  const { t, locale } = useI18n();
  const navigate = useNavigate();
  const dbStatus = useKanaf((s) => s.dbStatus);
  const progress = useKanaf((s) => s.dbProgress);
  const findings = useKanaf((s) => s.findings.length);
  const scan = useKanaf((s) => s.scan);
  const lastScan = useKanaf((s) => s.lastScan);
  const shell = useKanaf((s) => s.shell);
  const realtime = useKanaf((s) => s.realtime);
  const note = useKanaf((s) => s.realtimeNote);
  const wifiOnly = useKanaf((s) => s.settings.wifiOnly);
  const integrity = useKanaf((s) => s.integrity);
  const [link, setLink] = useState("");
  const [askData, setAskData] = useState(false);
  const ready = dbStatus === "ready" && !scan.running;
  const valid = link.trim().length > 0;

  async function goLink() {
    if (!valid || !ready) return;
    await navigate({ to: "/phish", search: { text: link.trim() } });
  }

  return (
    <Frame>
      <HomeBar />
      <Notice />
      {dbStatus === "loading" ? (
        <p className="mb-3 text-center text-sm text-muted" role="status">
          {t.preparing} {progress}%
        </p>
      ) : null}
      {dbStatus === "error" ? <p className="mb-3 text-center text-sm text-gold">{t.failedDb}</p> : null}
      {!scan.running && lastScan && findings === 0 ? (
        <p className="mb-3 text-center text-sm text-teal">{scanSummary(locale, lastScan.files)}</p>
      ) : null}
      {shell === "android" && !scan.running && !lastScan ? <p className="mb-3 text-center text-xs leading-relaxed text-muted">{t.deviceHint}</p> : null}

      {integrity === "repacked" ? <p className="mb-3 text-center text-sm text-gold">{t.integrityBad}</p> : null}

      <section className="overflow-hidden rounded-3xl border border-line bg-ink-2">
        <div className="bg-[radial-gradient(circle_at_50%_0%,rgba(32,201,151,0.16),transparent_62%)] px-4 py-4">
          <div className="flex items-center gap-3">
            <button
              type="button"
              disabled={!ready}
              onClick={() => void (shell === "android" ? scanDevice("deep") : chooseFolder("deep"))}
              className="grid h-14 w-14 shrink-0 place-items-center rounded-full border border-gold/50 bg-ink text-sm font-semibold text-cyan disabled:opacity-50"
              aria-label={t.scanDeep}
            >
              K
            </button>
            <div className="min-w-0 flex-1">
              <p className="text-base font-semibold leading-tight">
                {scan.running && scan.mode === "deep" ? `${t.scanning} ${scan.total ? Math.round((scan.done / scan.total) * 100) : 0}%` : t.scanDeep}
              </p>
              <p className="mt-1 text-xs leading-snug text-muted">{ready ? t.tagline : t.notReady}</p>
            </div>
          </div>
        </div>
        <div className={`grid border-t border-line ${shell === "android" && !scan.running ? "grid-cols-2" : "grid-cols-1"}`}>
          {scan.running ? (
            <button type="button" onClick={cancelScan} className="h-11 text-sm font-medium">
              {t.cancel}
            </button>
          ) : (
            <button type="button" disabled={!ready} onClick={() => void (shell === "android" ? scanDevice("quick") : chooseFolder("quick"))} className="h-11 text-sm font-medium disabled:opacity-50">
              {t.scanQuick}
            </button>
          )}
          {shell === "android" && !scan.running ? (
            <button type="button" disabled={!ready} onClick={() => void chooseFolder("deep")} className="h-11 border-s border-line text-sm font-medium disabled:opacity-50">
              {t.scanFolder}
            </button>
          ) : null}
        </div>
      </section>
      {scan.running ? (
        <p className="mt-2 truncate text-center text-xs text-muted">
          <bdi>{scan.phase === "enum" ? t.listing : scan.current}</bdi>
        </p>
      ) : null}
      {findings > 0 ? (
        <Link to="/results" className="mt-3 flex h-11 items-center justify-center rounded-xl bg-gold/15 text-sm font-semibold text-gold">
          {resultsLabel(locale, findings)}
        </Link>
      ) : null}
      {lastScan && lastScan.downloads === false && !scan.running ? <p className="mt-2 text-center text-xs text-muted">{t.downloadsClosed}</p> : null}

      <form
        className="mt-3"
        onSubmit={(event) => {
          event.preventDefault();
          void goLink();
        }}
      >
        <label className="mb-2 block text-xs font-semibold text-muted" htmlFor="kanaf-check">
          {t.phishTitle}
        </label>
        <div className="flex gap-2">
          <input
            id="kanaf-check"
            value={link}
            onChange={(event) => setLink(event.target.value)}
            placeholder={t.paste}
            className="h-11 min-w-0 flex-1 rounded-xl border border-line bg-ink-2 px-3 text-sm text-fg outline-none"
            aria-label={t.paste}
          />
          <button type="submit" disabled={!ready || !valid} className="h-11 shrink-0 rounded-xl bg-gold px-4 text-sm font-semibold text-ink disabled:opacity-50">
            {t.scanLink}
          </button>
        </div>
      </form>
      <Link to="/qr" className="mt-2 flex h-11 items-center justify-center rounded-xl border border-line bg-ink-2 text-sm font-medium">
        {t.qrTitle}
      </Link>

      <div className="mt-3 grid grid-cols-2 gap-2">
        <button type="button" onClick={() => void navigate({ to: "/messages", search: { auto: shell === "android" } })} className="flex h-11 items-center justify-center rounded-xl border border-line bg-ink-2 px-2 text-center text-sm font-medium">
          {t.homeMsg}
        </button>
        <button
          type="button"
          disabled={!ready}
          onClick={() => {
            void chooseFiles().then((result) => {
              if (result === "clean" || result === "hit") void navigate({ to: "/checked" });
            });
          }}
          className="flex h-11 items-center justify-center rounded-xl border border-line bg-ink-2 px-2 text-center text-sm font-medium disabled:opacity-50"
        >
          {t.homeFile}
        </button>
        <Link to="/behavior" className="flex h-11 items-center justify-center rounded-xl border border-line bg-ink-2 px-2 text-center text-sm font-medium">
          {t.engineBehavior}
        </Link>
        <Link to="/advisor" className="flex h-11 items-center justify-center rounded-xl border border-line bg-ink-2 px-2 text-center text-sm font-medium">
          {t.homeAdvisor}
        </Link>
      </div>
      <div className="mt-2 grid grid-cols-2 gap-2">
        <button
          type="button"
          disabled={dbStatus !== "ready" || progress < 100}
          onClick={() => {
            if (wifiOnly && metered() === true) {
              setAskData(true);
              return;
            }
            void refreshSources(false);
          }}
          className="flex h-10 items-center justify-center rounded-xl border border-line bg-ink-2 text-sm font-medium disabled:opacity-50"
        >
          {dbStatus === "ready" && progress < 100 ? `${t.updating} ${progress}%` : t.homeUpdate}
        </button>
        <Link to="/settings/device" className="flex h-10 items-center justify-center rounded-xl border border-line bg-ink-2 text-sm font-medium">
          {t.deviceTitle}
        </Link>
      </div>
      <div className="mt-1 flex items-stretch gap-2">
        <Link to="/settings" className="flex h-11 shrink-0 items-center justify-center rounded-xl border border-line bg-ink-2 px-3 text-sm font-medium">
          {t.settings}
        </Link>
        <button
          type="button"
          role="switch"
          aria-checked={realtime}
          aria-label={t.ariaSwitch}
          onClick={() => void setRealtime(!realtime)}
          className={`flex h-11 min-w-0 flex-1 items-center justify-center rounded-xl border px-3 text-sm font-medium ${realtime ? "border-teal bg-ink-2 text-teal" : "border-line bg-ink-2"}`}
        >
          {t.realtime}
        </button>
      </div>
      {note === "need" ? <p className="mt-3 text-sm text-gold">{t.realtimeNeed}</p> : null}
      {note === "missing" ? <p className="mt-3 text-sm text-muted">{t.realtimeMissing}</p> : null}
      {note === "fail" ? <p className="mt-3 text-sm text-gold">{t.realtimeFail}</p> : null}
      {note === "watching" ? <p className="mt-3 text-sm text-teal">{shell === "android" ? t.liveAndroid : t.liveWatching}</p> : null}
      {askData ? (
        <div className="glass mt-3 p-4 text-sm">
          <p>{t.cellularWarn}</p>
          <button
            type="button"
            className="mt-3 min-h-12 w-full rounded-2xl bg-gold font-semibold text-ink"
            onClick={() => {
              setAskData(false);
              void refreshSources(true);
            }}
          >
            {t.downloadAnyway}
          </button>
        </div>
      ) : null}
    </Frame>
  );
}
