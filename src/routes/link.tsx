import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Bidi, Confirm, Frame, TopBar } from "@/components/kanaf/chrome";
import { reasonLines } from "@/components/kanaf/reasons";
import { useI18n } from "@/lib/kanaf/i18n";
import { rememberUrl, scanLink, tryRedirect } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";
import type { UrlFinding } from "@/lib/kanaf/engine/url";

export const Route = createFileRoute("/link")({
  validateSearch: (search: Record<string, unknown>) => ({ url: typeof search.url === "string" ? search.url : "" }),
  component: LinkScan,
});

function LinkScan() {
  const { url } = Route.useSearch();
  const { t } = useI18n();
  const ready = useKanaf((s) => s.dbStatus === "ready");
  const [result, setResult] = useState<UrlFinding | null>(null);
  const [open, setOpen] = useState(false);
  const [expandNote, setExpandNote] = useState("");

  useEffect(() => {
    if (!ready || !url) return;
    void scanLink(url).then(setResult);
  }, [ready, url]);

  const label =
    result?.verdict === "malicious" ? t.malicious : result?.verdict === "suspicious" ? t.suspicious : t.noIndicators;
  return (
    <Frame>
      <TopBar title={t.linkTitle} />
      <p className="glass p-4 text-sm">
        <Bidi>{url}</Bidi>
      </p>
      {!result ? <p className="mt-3 text-sm text-muted">{ready ? t.working : t.notReady}</p> : null}
      {result ? (
        <article className="glass mt-3 p-4">
          <p className={result.verdict === "clean" ? "text-teal" : "text-gold"}>{label}</p>
          <ul className="mt-2 space-y-2 text-sm">
            {result.reasons.map((reason) => (
              <li key={reason}>{reasonLines(t, reason, result.host)[0]?.text}</li>
            ))}
            {result.reasons.length === 0 ? <li>{t.noIndicators}</li> : null}
          </ul>
          <div className="mt-4 flex flex-col gap-3">
            {result.verdict !== "clean" ? (
              <button type="button" className="min-h-12 rounded-2xl bg-teal font-semibold text-teal-ink" onClick={() => void rememberUrl(result.normalized)}>
                {t.allowAddress}
              </button>
            ) : null}
            <button type="button" className="min-h-12 rounded-2xl border border-line" onClick={() => setOpen(true)}>
              {t.open}
            </button>
            <button
              type="button"
              className="min-h-12 rounded-2xl border border-gold text-sm text-gold"
              onClick={() => {
                setExpandNote(t.expandWarn);
                void tryRedirect(result.normalized).then((step) => {
                  setExpandNote(step.ok && step.final ? step.final : t.expandFail);
                });
              }}
            >
              {t.expand}
            </button>
            {expandNote ? (
              <p className="text-sm text-muted">
                <Bidi>{expandNote}</Bidi>
              </p>
            ) : null}
          </div>
        </article>
      ) : null}
      {open && result ? (
        <Confirm
          title={t.open}
          body={t.confirmOpen}
          confirm={t.open}
          onClose={() => setOpen(false)}
          onConfirm={() => {
            window.open(result.normalized, "_blank", "noopener,noreferrer");
            setOpen(false);
          }}
        />
      ) : null}
    </Frame>
  );
}
