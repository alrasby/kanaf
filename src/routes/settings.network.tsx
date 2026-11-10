import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Frame, TopBar } from "@/components/kanaf/chrome";
import { useI18n } from "@/lib/kanaf/i18n";
import { metered, networkKind, saveSettings } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/settings/network")({ component: Network });

function Network() {
  const { t } = useI18n();
  const settings = useKanaf((s) => s.settings);
  const shell = useKanaf((s) => s.shell);
  const kind = networkKind();
  const line = kind === "wifi" ? t.connectionWifi : kind === "cellular" ? t.connectionCell : kind === "none" ? t.connectionNone : t.connectionUnknown;
  const [access, setAccess] = useState<"on" | "off" | "web">("web");
  useEffect(() => {
    const read = () => {
      const native = (window as Window & { KanafNative?: { notices?: () => string } }).KanafNative;
      if (!native?.notices) return;
      setAccess(native.notices() === "on" ? "on" : "off");
    };
    read();
    window.addEventListener("focus", read);
    return () => window.removeEventListener("focus", read);
  }, []);
  return (
    <Frame>
      <TopBar title={t.networkTitle} />
      <label className="glass flex min-h-14 items-center justify-between gap-3 px-4 text-sm">
        {t.wifiOnly}
        <input type="checkbox" checked={settings.wifiOnly} onChange={(event) => void saveSettings({ ...settings, wifiOnly: event.target.checked })} />
      </label>
      <label className="glass mt-3 flex min-h-14 items-center justify-between gap-3 px-4 text-sm">
        {t.engineCloud}
        <input type="checkbox" checked={settings.cloudFeeds} onChange={(event) => void saveSettings({ ...settings, cloudFeeds: event.target.checked })} />
      </label>
      <p className="mt-3 text-sm leading-relaxed text-muted">{t.cloudHint}</p>
      <p className="mt-2 text-sm text-muted">{line}</p>
      {metered() === true ? <p className="mt-2 text-sm text-gold">{t.cellularWarn}</p> : null}
      {shell === "android" ? (
        <section className="mt-4">
          <h2 className="text-sm font-semibold">{t.notices}</h2>
          <p className="mt-2 text-sm leading-relaxed text-muted">{t.noticesLead}</p>
          <button
            type="button"
            className="mt-2 h-10 w-full rounded-xl border border-line text-sm"
            onClick={() => {
              const native = (window as Window & { KanafNative?: { openSettings?: (kind: string) => void; notices?: () => string } }).KanafNative;
              native?.openSettings?.("notices");
              setAccess(native?.notices?.() === "on" ? "on" : "off");
            }}
          >
            {t.noticesOpen}
          </button>
          {access !== "web" ? <p className="mt-2 text-sm text-muted">{access === "on" ? t.noticesOn : t.noticesOff}</p> : null}
        </section>
      ) : null}
    </Frame>
  );
}