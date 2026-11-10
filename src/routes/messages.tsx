import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Bidi, Frame, TopBar } from "@/components/kanaf/chrome";
import { reasonLines } from "@/components/kanaf/reasons";
import { useI18n } from "@/lib/kanaf/i18n";
import { inspectMessage, keepMessageFinding, askCloud, saveSettings, scanInbox, type InboxHit } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/messages")({
  validateSearch: (search: Record<string, unknown>) => ({
    auto: search.auto === true || search.auto === "1" || search.auto === "true" || search.auto === 1,
  }),
  component: Messages,
});

function Messages() {
  const { t } = useI18n();
  const { auto } = Route.useSearch();
  const ready = useKanaf((s) => s.dbStatus === "ready");
  const shell = useKanaf((s) => s.shell);
  const settings = useKanaf((s) => s.settings);
  const [cloudNote, setCloudNote] = useState("");
  const [reading, setReading] = useState(false);
  const [sender, setSender] = useState("");
  const [text, setText] = useState("");
  const [verdict, setVerdict] = useState("");
  const [lines, setLines] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState("");
  const [status, setStatus] = useState("");
  const [hits, setHits] = useState<InboxHit[]>([]);

  async function runInbox() {
    if (!ready || running) return;
    setRunning(true);
    setStatus("");
    setHits([]);
    const result = await scanInbox((done, total) => setProgress(`${done}/${total}`));
    setRunning(false);
    setProgress("");
    setStatus(result.status);
    setHits(result.hits);
  }

  useEffect(() => {
    if (!auto || !ready || shell !== "android") return;
    void runInbox();
    // The inbox scan should start once when the home button opens this page.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, ready, shell]);

  return (
    <Frame>
      <TopBar title={t.messagesTitle} />
      <p className="mb-3 text-sm leading-relaxed text-muted">{t.inboxHint}</p>
      <button
        type="button"
        disabled={!ready || running || shell !== "android"}
        className="h-10 w-full rounded-xl bg-teal text-sm font-semibold text-teal-ink disabled:opacity-50"
        onClick={() => void runInbox()}
      >
        {running ? `${t.inboxProgress} ${progress}` : t.scanInbox}
      </button>
      {shell !== "android" ? <p className="mt-2 text-sm text-muted">{t.inboxWeb}</p> : null}
      {status === "denied" ? <p className="mt-2 text-sm text-gold">{t.inboxDenied}</p> : null}
      {status === "ok" && hits.length === 0 ? <p className="mt-2 text-sm text-teal">{t.inboxEmpty}</p> : null}
      {status === "empty" ? <p className="mt-2 text-sm text-muted">{t.inboxEmpty}</p> : null}
      <ul className="mt-3 space-y-2">
        {hits.map((hit, index) => (
          <li key={`${hit.from}-${hit.detail}-${index}`} className="glass p-3 text-sm">
            <p className="font-semibold">{hit.verdict === "malicious" ? t.malicious : t.suspicious}</p>
            <p className="mt-1 text-muted">
              {t.sender} <Bidi>{hit.from || "—"}</Bidi>
            </p>
            {hit.file ? (
              <p className="text-muted">
                {t.homeFile} <Bidi>{hit.file}</Bidi>
              </p>
            ) : null}
            {hit.detail ? (
              <p>
                <Bidi>{hit.detail}</Bidi>
              </p>
            ) : null}
            <ul className="mt-1 space-y-1">
              {hit.reasons.flatMap((reason) => reasonLines(t, reason, hit.detail).map((line) => <li key={line.text}>{line.text}</li>))}
            </ul>
            {hit.excerpt ? <p className="mt-2 text-muted">{hit.excerpt}</p> : null}
          </li>
        ))}
      </ul>

      <p className="mb-3 mt-6 text-sm text-muted">{t.notStored}</p>
      <label className="mb-2 block text-sm">
        {t.sender}
        <input value={sender} onChange={(e) => setSender(e.target.value)} className="mt-1 h-10 w-full rounded-xl border border-line bg-ink-2 px-3 text-sm" />
      </label>
      <label className="mb-3 block text-sm">
        {t.message}
        <textarea value={text} onChange={(e) => setText(e.target.value)} rows={4} className="mt-1 w-full rounded-xl border border-line bg-ink-2 p-3 text-sm" />
      </label>
      <button
        type="button"
        disabled={!ready || !text.trim()}
        className="h-10 w-full rounded-xl border border-line text-sm font-semibold disabled:opacity-50"
        onClick={() => {
          const result = inspectMessage(sender, text);
          const label = result.verdict === "malicious" ? t.malicious : result.verdict === "suspicious" ? t.suspicious : t.noIndicators;
          setVerdict(label);
          const reasons = result.reasons.flatMap((reason) =>
            reasonLines(
              t,
              reason,
              reason === "lure-model" ? result.clause : reason === "lookalike" ? result.urls.find((url) => url.hint)?.hint || "" : result.urls[0]?.host ?? "",
            ).map((line) => line.text),
          );
          setLines(reasons);
          setText("");
          if (result.verdict !== "clean") {
            void keepMessageFinding(sender, result.fingerprint, result.reasons[0] ?? "heuristic", result.urls[0]?.host ?? "", result.verdict);
          }
        }}
      >
        {t.analyze}
      </button>
      <p className="mb-2 mt-4 text-sm text-muted">{t.readLead}</p>
      <label className="flex h-10 items-center justify-center rounded-xl border border-line text-sm font-medium">
        {reading ? t.working : t.readImage}
        <input
          type="file"
          accept="image/*"
          className="hidden"
          onChange={(event) => {
            const file = event.target.files?.[0];
            event.target.value = "";
            if (!file) return;
            setReading(true);
            setCloudNote("");
            void import("tesseract.js")
              .then(({ createWorker }) => createWorker("ara+eng"))
              .then(async (worker) => {
                try {
                  const found = await worker.recognize(file);
                  const sample = found.data.text.replace(/\s+/g, " ").trim();
                  if (!sample) {
                    setCloudNote(t.readEmpty);
                    return;
                  }
                  setText(sample);
                  setCloudNote("");
                } finally {
                  await worker.terminate();
                }
              })
              .catch(() => setCloudNote(t.readFail))
              .finally(() => setReading(false));
          }}
        />
      </label>
      <p className="mb-2 mt-4 text-sm text-muted">{t.cloudLead}</p>
      <input
        type="password"
        value={settings.cloudKey}
        autoComplete="off"
        placeholder={t.cloudKey}
        onChange={(event) => void saveSettings({ ...settings, cloudKey: event.target.value })}
        className="mb-2 h-10 w-full rounded-xl border border-line bg-ink-2 px-3 text-sm"
      />
      <button
        type="button"
        disabled={!text.trim()}
        className="h-10 w-full rounded-xl border border-line text-sm font-semibold disabled:opacity-50"
        onClick={() => {
          setCloudNote("");
          void askCloud(text, settings.cloudKey).then((result) => {
            if (result === "need") {
              setCloudNote(t.cloudNeed);
              return;
            }
            if (result === "fail") {
              setCloudNote(t.failed);
              return;
            }
            if (result.verdict === "clean") {
              setCloudNote(t.cloudClean);
              return;
            }
            setVerdict(t.suspicious);
            setLines(reasonLines(t, "cloud-lure", result.clause).map((line) => line.text));
            const local = inspectMessage(sender, text);
            void keepMessageFinding(sender, local.fingerprint, "cloud-lure", result.clause, "suspicious");
          });
        }}
      >
        {t.cloudSend}
      </button>
      {cloudNote ? <p className="mt-2 text-sm text-gold">{cloudNote}</p> : null}
      {verdict ? (
        <article className="glass mt-4 p-4 text-sm">
          <p className="font-semibold">{verdict}</p>
          <p className="mt-2 text-muted">
            {t.fingerprint} <Bidi>{sender || "—"}</Bidi>
          </p>
          <ul className="mt-2 space-y-1">
            {lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </article>
      ) : null}
    </Frame>
  );
}
