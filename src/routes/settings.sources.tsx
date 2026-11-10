import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Bidi, Frame, TopBar } from "@/components/kanaf/chrome";
import { formatCount, useI18n } from "@/lib/kanaf/i18n";
import { runEicar } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/settings/sources")({ component: Sources });

function Sources() {
  const { t, locale } = useI18n();
  const sources = useKanaf((s) => s.sources);
  const status = useKanaf((s) => s.dbStatus);
  const [note, setNote] = useState("");
  return (
    <Frame>
      <TopBar title={t.sourcesTitle} />
      <p className="mb-3 text-sm leading-relaxed text-muted">{t.cloudHonest}</p>
      <ul className="space-y-3">
        {sources.map((source) => (
          <li key={source.id} className="glass p-4 text-sm">
            <p className="font-semibold">
              <Bidi>{source.id}</Bidi>
            </p>
            <p className="mt-1 text-muted">
              {t.version} <Bidi>{source.version}</Bidi>
            </p>
            <p className="text-muted">
              {t.updated} <Bidi>{source.updatedAt}</Bidi>
            </p>
            {source.state === "ready" ? (
              <p>
                {t.count} <Bidi>{formatCount(locale, source.count)}</Bidi>
              </p>
            ) : (
              <p>{source.state === "loading" ? t.downloading : source.state === "failed" ? t.failed : t.notLoaded}</p>
            )}
            {source.error ? <p className="text-gold">{source.error}</p> : null}
            <p className="mt-2 text-muted">{source.license}</p>
            <a className="text-teal" href={source.terms} target="_blank" rel="noreferrer">
              {t.sourceTerms}
            </a>
          </li>
        ))}
      </ul>
      <section className="mt-5">
        <h2 className="text-sm font-semibold">{t.selfTest}</h2>
        <p className="mt-1 text-sm text-muted">{t.eicarHelp}</p>
        <button
          type="button"
          disabled={status !== "ready"}
          className="mt-3 min-h-12 w-full rounded-2xl border border-gold text-gold disabled:opacity-50"
          onClick={() => {
            void runEicar().then((hit) => setNote(hit ? t.eicarHit : t.eicarMiss));
          }}
        >
          {t.eicar}
        </button>
        {note ? <p className="mt-2 text-sm">{note}</p> : null}
      </section>
    </Frame>
  );
}
