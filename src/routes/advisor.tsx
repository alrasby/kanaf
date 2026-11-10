import { createFileRoute } from "@tanstack/react-router";
import { Frame, TopBar } from "@/components/kanaf/chrome";
import { adviceLabel, useI18n } from "@/lib/kanaf/i18n";
import { openDeviceSettings } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/advisor")({ component: Advisor });

function Advisor() {
  const { t, locale } = useI18n();
  const sources = useKanaf((s) => s.sources);
  const findings = useKanaf((s) => s.findings.length);
  const realtime = useKanaf((s) => s.realtime);
  const dbStatus = useKanaf((s) => s.dbStatus);
  const shell = useKanaf((s) => s.shell);
  const device = useKanaf((s) => s.device);
  const stale = sources.some((source) => {
    const time = Date.parse(source.updatedAt);
    return Number.isFinite(time) && Date.now() - time > 7 * 86400000;
  });
  const notify = typeof Notification !== "undefined" ? Notification.permission : "default";
  const insecure = shell !== "android" && typeof window !== "undefined" && !window.isSecureContext;
  const tips = [
    stale || dbStatus !== "ready" ? t.advisorStale : null,
    findings > 0 ? t.advisorPending : null,
    !realtime ? t.advisorLive : null,
    notify === "denied" ? t.advisorNotify : null,
    insecure ? t.advisorInsecure : null,
  ].filter((tip): tip is string => Boolean(tip));
  const rows =
    shell === "android" && device
      ? [
          { label: t.lock, value: device.lock ? t.lockOn : t.lockOff, bad: !device.lock },
          { label: t.patch, value: device.patch || t.off, bad: false },
          { label: t.usb, value: device.usb ? t.usbOn : t.usbOff, bad: device.usb },
          { label: t.developer, value: device.developer ? t.devOn : t.devOff, bad: device.developer },
        ]
      : null;
  return (
    <Frame>
      <TopBar title={t.advisorTitle} />
      <p className="text-lg font-semibold">{adviceLabel(locale, tips.length)}</p>
      {tips.length === 0 ? <p className="mt-2 text-sm text-teal">{t.noAdvice}</p> : null}
      <ul className="mt-3 space-y-2">
        {tips.map((tip) => (
          <li key={tip} className="glass px-4 py-3 text-sm">
            {tip}
          </li>
        ))}
      </ul>
      {rows ? (
        <>
          <h2 className="mt-6 text-sm font-semibold text-gold">{t.deviceLead}</h2>
          <ul className="mt-2 space-y-2 text-sm">
            {rows.map((row) => (
              <li key={row.label} className="glass px-4 py-3">
                <p className="text-muted">{row.label}</p>
                <p className={row.bad ? "mt-1 text-gold" : "mt-1 text-teal"}>{row.value}</p>
              </li>
            ))}
          </ul>
          <button
            type="button"
            onClick={() => openDeviceSettings("security")}
            className="mt-3 min-h-12 w-full rounded-2xl border border-line text-sm"
          >
            {t.openSettings}
          </button>
        </>
      ) : (
        <>
          <h2 className="mt-6 text-sm font-semibold text-gold">{t.unavailable}</h2>
          <p className="mt-2 text-sm text-muted">{t.unavailableBody}</p>
          <ul className="mt-2 space-y-2 text-sm">
            {[t.lock, t.patch, t.usb, t.developer].map((item) => (
              <li key={item} className="glass px-4 py-3 text-muted">
                {item}
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="mt-4 text-sm text-muted">{t.cannotChange}</p>
    </Frame>
  );
}