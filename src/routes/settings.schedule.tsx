import { createFileRoute } from "@tanstack/react-router";
import { Frame, TopBar } from "@/components/kanaf/chrome";
import { useI18n } from "@/lib/kanaf/i18n";
import { saveSettings } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/settings/schedule")({ component: Schedule });

function Schedule() {
  const { t } = useI18n();
  const settings = useKanaf((s) => s.settings);
  const shell = useKanaf((s) => s.shell);
  return (
    <Frame>
      <TopBar title={t.scheduleTitle} />
      <p className="mb-4 text-sm text-muted">{shell === "android" ? t.limitApp5 : t.scheduleHelp}</p>
      <label className="glass flex min-h-14 items-center justify-between px-4 text-sm">
        {t.enable}
        <input
          type="checkbox"
          checked={settings.scheduleEnabled}
          onChange={(event) => void saveSettings({ ...settings, scheduleEnabled: event.target.checked })}
        />
      </label>
      <div className="mt-3 grid grid-cols-2 gap-2">
        <button type="button" className={`min-h-12 rounded-2xl border ${settings.every === "day" ? "border-teal text-teal" : "border-line"}`} onClick={() => void saveSettings({ ...settings, every: "day" })}>
          {t.daily}
        </button>
        <button type="button" className={`min-h-12 rounded-2xl border ${settings.every === "week" ? "border-teal text-teal" : "border-line"}`} onClick={() => void saveSettings({ ...settings, every: "week" })}>
          {t.weekly}
        </button>
      </div>
      <label className="glass mt-3 flex min-h-14 items-center justify-between px-4 text-sm">
        {t.charging}
        <input type="checkbox" checked={settings.chargingOnly} onChange={(event) => void saveSettings({ ...settings, chargingOnly: event.target.checked })} />
      </label>
    </Frame>
  );
}
