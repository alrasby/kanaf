import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { Bidi, Confirm, Frame, TopBar } from "@/components/kanaf/chrome";
import { reasonLines } from "@/components/kanaf/reasons";
import { formatCount, useI18n } from "@/lib/kanaf/i18n";
import { allowFinding, deleteFinding, quarantineFinding } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/decision/$id")({ component: Decision });

function Decision() {
  const { id } = Route.useParams();
  const { t, locale } = useI18n();
  const navigate = useNavigate();
  const finding = useKanaf((s) => s.findings.find((item) => item.id === id));
  const [ask, setAsk] = useState<null | "delete" | "vault">(null);
  if (!finding) {
    return (
      <Frame>
        <TopBar title={t.decisionTitle} />
        <p className="text-sm text-muted">{t.emptyResults}</p>
      </Frame>
    );
  }
  const lines = reasonLines(t, finding.reasonId, finding.detail);
  const file = finding.kind === "file";
  return (
    <Frame>
      <TopBar title={t.decisionTitle} />
      <article className="glass p-4">
        <h2 className="text-lg font-semibold">
          <Bidi>{finding.name}</Bidi>
        </h2>
        <p className="mt-1 text-xs text-gold">{finding.verdict === "malicious" ? t.malicious : t.suspicious}</p>
        <h3 className="mt-4 text-sm text-muted">{t.reason}</h3>
        <ul className="mt-1 space-y-2 text-sm leading-relaxed">
          {lines.map((line) => (
            <li key={line.text}>
              {line.text} {line.detail ? <Bidi>{line.detail}</Bidi> : null}
            </li>
          ))}
        </ul>
        <h3 className="mt-4 text-sm text-muted">{t.permissions}</h3>
        {finding.permissions.length === 0 ? <p className="text-sm">{t.noPerms}</p> : null}
        <ul className="mt-1 space-y-1 text-sm">
          {finding.permissions.map((perm) => (
            <li key={perm}>
              <Bidi>{perm}</Bidi>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-muted">
          {t.bytes} <Bidi>{formatCount(locale, finding.size)}</Bidi>
        </p>
        {finding.kind === "url" ? <p className="mt-3 text-sm text-muted">{t.linkNoVault}</p> : null}
        {finding.kind === "message" ? <p className="mt-3 text-sm text-muted">{t.messageNoDelete}</p> : null}
      </article>
      <div className="mt-4 flex flex-col gap-3">
        <button
          type="button"
          className="min-h-12 rounded-2xl bg-teal font-semibold text-teal-ink"
          onClick={() => {
            void allowFinding(finding.id).then(() => navigate({ to: "/results" }));
          }}
        >
          {finding.kind === "url" ? t.allowAddress : t.allow}
        </button>
        {file ? (
          <button type="button" className="min-h-12 rounded-2xl border border-gold text-gold" onClick={() => setAsk("vault")}>
            {t.quarantine}
          </button>
        ) : null}
        {file ? (
          <button type="button" className="min-h-12 rounded-2xl bg-danger font-semibold" onClick={() => setAsk("delete")}>
            {t.delete}
          </button>
        ) : null}
      </div>
      {ask === "delete" ? (
        <Confirm
          title={t.delete}
          body={t.confirmDelete}
          confirm={t.yesDelete}
          danger
          onClose={() => setAsk(null)}
          onConfirm={() => {
            void deleteFinding(finding.id).then((ok) => {
              setAsk(null);
              if (ok) void navigate({ to: "/results" });
            });
          }}
        />
      ) : null}
      {ask === "vault" ? (
        <Confirm
          title={t.quarantine}
          body={t.confirmVault}
          confirm={t.confirm}
          onClose={() => setAsk(null)}
          onConfirm={() => {
            void quarantineFinding(finding.id).then(() => navigate({ to: "/results" }));
          }}
        />
      ) : null}
    </Frame>
  );
}
