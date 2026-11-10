import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Frame, TopBar } from "@/components/kanaf/chrome";
import { formatCount, useI18n, type Copy } from "@/lib/kanaf/i18n";
import { saveDecisions } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/settings/log")({ component: LogPage });

const LINK_REASONS = new Set(["listed", "ip-host", "shortener", "punycode", "lookalike", "userinfo", "brand-host", "doc-link"]);
const PHONE_REASONS = new Set(["premium-rate", "callback-lure"]);

function LogPage() {
  const { t, locale } = useI18n();
  const log = useKanaf((s) => s.log);
  const findings = useKanaf((s) => s.findings);
  const [note, setNote] = useState("");
  const weekAgo = Date.now() - 7 * 86400000;
  const week = findings.filter((item) => item.createdAt >= weekAgo);
  const messages = week.filter((item) => item.kind === "message").length;
  const links = week.filter((item) => item.kind === "url" || LINK_REASONS.has(item.reasonId)).length;
  const phones = week.filter((item) => PHONE_REASONS.has(item.reasonId)).length;
  const modes: Record<string, keyof Copy> = {
    deep: "modeDeep",
    quick: "modeQuick",
    custom: "modeCustom",
    scheduled: "modeScheduled",
    live: "modeLive",
  };
  return (
    <Frame>
      <TopBar title={t.logTitle} />
      <section className="mb-4 glass p-4 text-sm">
        <p className="font-semibold">{t.weekTitle}</p>
        <p className="mt-2 text-muted">
          {t.weekMessages} {formatCount(locale, messages)}
        </p>
        <p className="text-muted">
          {t.weekLinks} {formatCount(locale, links)}
        </p>
        <p className="text-muted">
          {t.weekPhones} {formatCount(locale, phones)}
        </p>
        <button
          type="button"
          className="mt-3 h-10 w-full rounded-xl border border-line text-sm font-medium"
          onClick={() => {
            const lines = [
              "Kanaf week",
              new Date().toISOString(),
              `messages ${messages}`,
              `links ${links}`,
              `phones ${phones}`,
              "",
              ...week.map((item) => `${item.kind}\t${item.reasonId}\t${item.name}\t${item.detail}`),
            ];
            const text = lines.join("\n");
            const native = (window as Window & { KanafNative?: { saveText?: (name: string, body: string) => string } }).KanafNative;
            if (native?.saveText) {
              setNote(native.saveText("kanaf-week.txt", text) === "ok" ? t.exported : t.failed);
              return;
            }
            const blob = new Blob([text], { type: "text/plain" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = "kanaf-week.txt";
            link.click();
            URL.revokeObjectURL(url);
            setNote(t.exported);
          }}
        >
          {t.weekExport}
        </button>
      </section>
      <button
        type="button"
        className="mb-3 h-10 w-full rounded-xl border border-line text-sm font-medium"
        onClick={() => {
          void saveDecisions().then((result) => setNote(result === "empty" ? t.exportEmpty : result === "fail" ? t.failed : t.exported));
        }}
      >
        {t.exportDecisions}
      </button>
      {note ? <p className="mb-3 text-sm text-teal">{note}</p> : null}
      {log.length === 0 ? <p className="text-sm text-muted">{t.logEmpty}</p> : null}
      <ul className="space-y-3">
        {log.map((entry) => (
          <li key={entry.id} className="glass p-4 text-sm">
            <p className="font-semibold">{t[modes[entry.mode]]}</p>
            <p className="text-muted">{new Date(entry.startedAt).toISOString().slice(0, 16).replace("T", " ")}</p>
            <p>
              {t.files} {formatCount(locale, entry.files)} · {t.findings} {formatCount(locale, entry.findings)} · {t.skipped}{" "}
              {formatCount(locale, entry.skipped)}
            </p>
            <p>{entry.status === "done" ? t.statusDone : entry.status === "cancelled" ? t.statusCancelled : t.failed}</p>
          </li>
        ))}
      </ul>
    </Frame>
  );
}
