import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Bidi, Confirm, Frame, TopBar } from "@/components/kanaf/chrome";
import { useI18n } from "@/lib/kanaf/i18n";
import { purgeVault, restoreVault, revokeAllow } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/quarantine")({ component: Quarantine });

function Quarantine() {
  const { t } = useI18n();
  const vault = useKanaf((s) => s.vault);
  const allow = useKanaf((s) => s.allow);
  const [ask, setAsk] = useState<null | { id: string; kind: "purge" | "restore" }>(null);
  return (
    <Frame>
      <TopBar title={t.quarantineTitle} />
      <p className="mb-3 text-sm text-muted">{t.vaultHelp}</p>
      <h2 className="text-sm font-semibold text-gold">{t.vault}</h2>
      {vault.length === 0 ? <p className="mt-2 text-sm text-muted">{t.emptyVault}</p> : null}
      <ul className="mt-2 space-y-3">
        {vault.map((item) => (
          <li key={item.id} className="glass p-4">
            <p className="font-medium">
              <Bidi>{item.name}</Bidi>
            </p>
            <div className="mt-3 flex gap-2">
              <button type="button" className="min-h-12 flex-1 rounded-2xl bg-teal text-sm font-semibold text-teal-ink" onClick={() => setAsk({ id: item.id, kind: "restore" })}>
                {t.restore}
              </button>
              <button type="button" className="min-h-12 flex-1 rounded-2xl bg-danger text-sm" onClick={() => setAsk({ id: item.id, kind: "purge" })}>
                {t.purge}
              </button>
            </div>
          </li>
        ))}
      </ul>
      <h2 className="mt-6 text-sm font-semibold text-gold">{t.allowed}</h2>
      {allow.length === 0 ? <p className="mt-2 text-sm text-muted">{t.emptyAllow}</p> : null}
      <ul className="mt-2 space-y-3">
        {allow.map((item) => (
          <li key={item.id} className="glass flex items-center justify-between gap-3 p-4">
            <Bidi>{item.name}</Bidi>
            <button type="button" className="min-h-12 shrink-0 rounded-2xl border border-line px-3 text-sm" onClick={() => void revokeAllow(item.id)}>
              {t.revoke}
            </button>
          </li>
        ))}
      </ul>
      {ask ? (
        <Confirm
          title={ask.kind === "purge" ? t.purge : t.restore}
          body={ask.kind === "purge" ? t.confirmPurge : t.confirmRestore}
          confirm={ask.kind === "purge" ? t.yesDelete : t.restore}
          danger={ask.kind === "purge"}
          onClose={() => setAsk(null)}
          onConfirm={() => {
            if (ask.kind === "purge") void purgeVault(ask.id);
            else void restoreVault(ask.id);
            setAsk(null);
          }}
        />
      ) : null}
    </Frame>
  );
}
