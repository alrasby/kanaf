import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Bidi, Frame, TopBar } from "@/components/kanaf/chrome";
import { reasonLines } from "@/components/kanaf/reasons";
import { behaviorResult, useI18n } from "@/lib/kanaf/i18n";
import { scanBehavior } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/behavior")({ component: Behavior });

function Behavior() {
  const { t, locale } = useI18n();
  const ready = useKanaf((s) => s.dbStatus === "ready");
  const shell = useKanaf((s) => s.shell);
  const allFindings = useKanaf((s) => s.findings);
  const findings = allFindings.filter((item) => item.reasonId === "heuristic");
  const [running, setRunning] = useState(false);
  const [note, setNote] = useState("");

  return (
    <Frame>
      <TopBar title={t.engineBehavior} />
      <p className="mb-3 text-sm leading-relaxed text-muted">{t.behaviorLead}</p>
      <button
        type="button"
        disabled={!ready || running || shell !== "android"}
        className="h-10 w-full rounded-xl bg-teal text-sm font-semibold text-teal-ink disabled:opacity-50"
        onClick={() => {
          setRunning(true);
          setNote("");
          void scanBehavior()
            .then((result) => {
              if (result === "web") setNote(t.behaviorWeb);
              else if (result === "fail") setNote(t.behaviorFail);
              else setNote(behaviorResult(locale, result.scanned, result.hits));
            })
            .catch(() => setNote(t.behaviorFail))
            .finally(() => setRunning(false));
        }}
      >
        {running ? t.working : t.behaviorScan}
      </button>
      {shell !== "android" ? <p className="mt-2 text-sm text-muted">{t.behaviorWeb}</p> : null}
      {note ? <p className={`mt-2 text-sm ${note === t.behaviorFail ? "text-gold" : "text-teal"}`}>{note}</p> : null}
      <ul className="mt-3 space-y-2">
        {findings.map((item) => (
          <li key={item.id} className="glass p-3 text-sm">
            <p className="font-semibold text-gold">{t.suspicious}</p>
            <p className="mt-1">
              <Bidi>{item.name}</Bidi>
            </p>
            <ul className="mt-1 space-y-1 text-muted">
              {reasonLines(t, item.reasonId, item.detail || "").map((line, index) => (
                <li key={`${item.id}-${index}`}>{line.text}</li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </Frame>
  );
}
