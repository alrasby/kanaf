import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Bidi, Frame, TopBar } from "@/components/kanaf/chrome";
import { reasonLines } from "@/components/kanaf/reasons";
import { extractUrls, normalizeUrl, type UrlFinding } from "@/lib/kanaf/engine/url";
import { analyzePhones, type PhoneFinding } from "@/lib/kanaf/engine/phone";
import { useI18n } from "@/lib/kanaf/i18n";
import { readClipboard, scanLink } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/phish")({
  validateSearch: (search: Record<string, unknown>) => ({ text: typeof search.text === "string" ? search.text : "" }),
  component: Phish,
});

function targetsFrom(raw: string): string[] {
  const found = extractUrls(raw);
  if (found.length) return found;
  const one = normalizeUrl(raw);
  return one ? [one.href] : [];
}

function Phish() {
  const { text } = Route.useSearch();
  const { t } = useI18n();
  const official = useKanaf((s) => s.settings.officialNumbers);
  const ready = useKanaf((s) => s.dbStatus === "ready");
  const [draft, setDraft] = useState(text);
  const [rows, setRows] = useState<UrlFinding[]>([]);
  const [phones, setPhones] = useState<PhoneFinding[]>([]);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  async function check(raw: string) {
    const targets = targetsFrom(raw);
    const foundPhones = analyzePhones(raw, official.map((row) => row.e164));
    const notable = foundPhones.filter((phone) => phone.verdict !== "clean");
    const shown = notable.length ? notable : targets.length === 0 && raw.trim().length < 24 ? foundPhones : [];
    if (!targets.length && !shown.length) {
      setRows([]);
      setPhones([]);
      setNote(t.phishEmptyClip);
      return;
    }
    setBusy(true);
    setNote("");
    const found: UrlFinding[] = [];
    for (const target of targets.slice(0, 12)) {
      const verdict = await scanLink(target);
      if (verdict) found.push(verdict);
    }
    setRows(found);
    setPhones(shown);
    setBusy(false);
  }

  useEffect(() => {
    if (!ready || !text) return;
    setDraft(text);
    void check(text);
    // Shared text should be checked once when the page opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, text]);

  return (
    <Frame>
      <TopBar title={t.phishTitle} />
      <p className="mb-3 text-sm leading-relaxed text-muted">{t.phishLead}</p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!ready || busy) return;
          void check(draft);
        }}
      >
        <textarea value={draft} onChange={(event) => setDraft(event.target.value)} rows={4} className="w-full rounded-xl border border-line bg-ink-2 p-3 text-sm" placeholder={t.paste} />
        <button type="submit" disabled={!ready || busy || !draft.trim()} className="mt-2 h-10 w-full rounded-xl bg-teal text-sm font-semibold text-teal-ink disabled:opacity-50">
          {busy ? t.working : t.scanLink}
        </button>
      </form>
      <button
        type="button"
        disabled={!ready || busy}
        className="mt-2 h-10 w-full rounded-xl border border-line text-sm disabled:opacity-50"
        onClick={() => {
          void readClipboard().then((copied) => {
            if (!copied.trim()) {
              setNote(t.phishEmptyClip);
              return;
            }
            setDraft(copied);
            void check(copied);
          });
        }}
      >
        {t.phishClip}
      </button>
      {note ? <p className="mt-2 text-sm text-muted">{note}</p> : null}
      <ul className="mt-3 space-y-2">
        {phones.map((phone) => (
          <li key={phone.e164} className="glass p-3 text-sm">
            <p className={phone.verdict === "clean" ? "font-semibold text-teal" : "font-semibold text-gold"}>
              {phone.verdict === "suspicious" ? t.suspicious : t.noIndicators}
            </p>
            <p className="mt-1">
              <Bidi>{phone.e164}</Bidi>
            </p>
            <ul className="mt-1 space-y-1 text-muted">
              {phone.reasons.map((reason) => (
                <li key={reason}>{reasonLines(t, reason, phone.e164)[0]?.text}</li>
              ))}
            </ul>
          </li>
        ))}
        {rows.map((row) => (
          <li key={row.normalized} className="glass p-3 text-sm">
            <p className={row.verdict === "clean" ? "font-semibold text-teal" : "font-semibold text-gold"}>
              {row.verdict === "malicious" ? t.malicious : row.verdict === "suspicious" ? t.suspicious : t.noIndicators}
            </p>
            <p className="mt-1">
              <Bidi>{row.normalized}</Bidi>
            </p>
            <ul className="mt-1 space-y-1 text-muted">
              {row.reasons.map((reason) => (
                <li key={reason}>{reasonLines(t, reason, reason === "lookalike" ? row.hint || row.host : row.host)[0]?.text}</li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </Frame>
  );
}
