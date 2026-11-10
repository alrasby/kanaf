import { createFileRoute, Link } from "@tanstack/react-router";
import { Bidi, Frame, TopBar } from "@/components/kanaf/chrome";
import { reasonLines } from "@/components/kanaf/reasons";
import { useI18n } from "@/lib/kanaf/i18n";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/results")({ component: Results });

function Results() {
  const { t } = useI18n();
  const findings = useKanaf((s) => s.findings);
  return (
    <Frame>
      <TopBar title={t.resultsTitle} />
      {findings.length === 0 ? <p className="text-sm text-muted">{t.emptyResults}</p> : null}
      <ul className="flex flex-col gap-3">
        {findings.map((item) => (
          <li key={item.id} className="glass p-4">
            <p className="font-semibold">
              <Bidi>{item.name}</Bidi>
            </p>
            <p className="mt-1 text-sm text-muted">{reasonLines(t, item.reasonId, item.detail)[0]?.text}</p>
            <p className="mt-1 text-xs uppercase tracking-wide text-gold">{item.verdict === "malicious" ? t.malicious : t.suspicious}</p>
            <Link
              to="/decision/$id"
              params={{ id: item.id }}
              className="mt-3 inline-flex min-h-12 items-center text-sm font-semibold text-teal"
            >
              {t.decide}
            </Link>
          </li>
        ))}
      </ul>
    </Frame>
  );
}
