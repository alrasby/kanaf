import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { Frame, TopBar } from "@/components/kanaf/chrome";
import { useI18n } from "@/lib/kanaf/i18n";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/settings/device")({ component: Device });

type SensorRow = { type: string; name: string };
type SimRow = { slot: number; kind: string; operator: string; radio: string; roaming: boolean; data: boolean };
type Info = {
  maker?: string;
  model?: string;
  release?: string;
  sdk?: number;
  patch?: string;
  board?: string;
  abis?: string;
  cores?: number;
  cpu?: string;
  ramTotal?: number;
  ramFree?: number;
  storeTotal?: number;
  storeFree?: number;
  level?: number;
  chargeUah?: number;
  temp?: number;
  voltage?: number;
  tech?: string;
  charging?: boolean;
  width?: number;
  height?: number;
  dpi?: number;
  sensors?: SensorRow[];
  built?: string;
  factory?: string;
  phone?: string;
  net?: { link?: string; vpn?: boolean };
  sims?: SimRow[];
};

function amount(bytes?: number): string {
  if (typeof bytes !== "number" || bytes <= 0) return "—";
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  return `${Math.round(bytes / 1_000_000)} MB`;
}

function Device() {
  const { t } = useI18n();
  const shell = useKanaf((s) => s.shell);
  const [info, setInfo] = useState<Info | null>(null);
  const asked = useRef(false);

  useEffect(() => {
    const read = () => {
      const native = (window as Window & { KanafNative?: { deviceInfo?: () => string; askPhoneState?: () => void } }).KanafNative;
      if (!native?.deviceInfo) return;
      try {
        const parsed = JSON.parse(native.deviceInfo()) as Info;
        setInfo(parsed);
        if (parsed.phone === "need" && !asked.current) {
          asked.current = true;
          native.askPhoneState?.();
        }
      } catch {
        setInfo(null);
      }
    };
    (window as Window & { __kanafDevice?: () => void }).__kanafDevice = read;
    read();
    return () => {
      delete (window as Window & { __kanafDevice?: () => void }).__kanafDevice;
    };
  }, []);

  const fullMah =
    info && info.level && info.level > 0 && info.level <= 100 && info.chargeUah && info.chargeUah > 0
      ? Math.round(info.chargeUah / 1000 / (info.level / 100))
      : 0;
  const cpuName = info?.cpu && info.cpu !== "unknown" ? info.cpu : info?.board && info.board !== "unknown" ? info.board : "";
  const cpu = [cpuName, info?.cores ? `${info.cores} cores` : "", info?.abis || ""].filter(Boolean).join(" · ") || "—";
  const rows: [string, string][] = info
    ? [
        ["Device", `${info.maker ?? ""} ${info.model ?? ""}`.trim()],
        ["Android", `${info.release ?? "—"} (API ${info.sdk ?? "—"})`],
        ["Security", info.patch || "—"],
        ["CPU", cpu],
        ["RAM", `${amount(info.ramFree)} free / ${amount(info.ramTotal)}`],
        ["Storage", `${amount(info.storeFree)} free / ${amount(info.storeTotal)}`],
        ["Battery", `${info.level ?? "—"}%${info.charging ? " charging" : ""}${info.tech ? ` · ${info.tech}` : ""}${fullMah ? ` · ~${fullMah} mAh` : ""}`],
        ["Temp", typeof info.temp === "number" && info.temp >= 0 ? `${(info.temp / 10).toFixed(1)} °C` : "—"],
        ["Voltage", typeof info.voltage === "number" && info.voltage > 0 ? `${info.voltage} mV` : "—"],
        ["Screen", info.width ? `${info.width}×${info.height} · ${info.dpi} dpi` : "—"],
        ["System build", info.built || "—"],
        ["Factory", info.factory || "Not exposed by Android"],
        ["Network", `${info.net?.link || "—"}${info.net?.vpn ? " · VPN" : ""}`],
      ]
    : [];
  const simRows: [string, string][] = (info?.sims ?? []).map((sim) => {
    const bits = [sim.operator || "—", sim.radio, sim.data ? "data" : "", sim.roaming ? "roaming" : ""].filter(Boolean);
    return [`${sim.kind} ${sim.slot}`, bits.join(" · ")];
  });

  return (
    <Frame>
      <TopBar title={t.deviceTitle} />
      <p className="mb-3 text-sm leading-relaxed text-muted">{t.devicePageLead}</p>
      {shell !== "android" ? <p className="text-sm text-muted">{t.cleanWeb}</p> : null}
      <ul dir="ltr" className="space-y-2 text-left">
        {rows.map(([label, value]) => (
          <li key={label} className="glass p-3 text-sm">
            <p className="text-xs text-muted">{label}</p>
            <p className="mt-1 font-medium break-normal text-cyan [word-break:normal]">{value}</p>
          </li>
        ))}
        {simRows.map(([label, value]) => (
          <li key={label} className="glass p-3 text-sm">
            <p className="text-xs text-muted">{label}</p>
            <p className="mt-1 font-medium break-normal text-cyan [word-break:normal]">{value}</p>
          </li>
        ))}
        {info?.phone === "ok" && simRows.length === 0 ? (
          <li className="glass p-3 text-sm">
            <p className="text-xs text-muted">SIM</p>
            <p className="mt-1 font-medium text-cyan">No active SIM or eSIM</p>
          </li>
        ) : null}
      </ul>
      {info?.sensors?.length ? (
        <ul dir="ltr" className="mt-3 space-y-1 text-left text-sm text-cyan">
          {info.sensors.map((sensor) => (
            <li key={sensor.type} className="break-normal [word-break:normal]">
              {sensor.type}
              {sensor.name ? ` · ${sensor.name}` : ""}
            </li>
          ))}
        </ul>
      ) : null}
    </Frame>
  );
}
