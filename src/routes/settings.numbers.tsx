import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Bidi, Frame, TopBar } from "@/components/kanaf/chrome";
import { normalizePhone } from "@/lib/kanaf/engine/phone";
import { useI18n } from "@/lib/kanaf/i18n";
import { saveSettings } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";
import type { OfficialNumber } from "@/lib/kanaf/types";

export const Route = createFileRoute("/settings/numbers")({ component: Numbers });

function Numbers() {
  const { t } = useI18n();
  const settings = useKanaf((s) => s.settings);
  const shell = useKanaf((s) => s.shell);
  const [label, setLabel] = useState("");
  const [number, setNumber] = useState("");
  const [role, setRole] = useState("");
  const [bad, setBad] = useState(false);
  const [fileNote, setFileNote] = useState("");

  function mergeBook(text: string) {
    try {
      const parsed = JSON.parse(text) as { kanaf?: string; official?: OfficialNumber[]; blocked?: string[] };
      if (parsed.kanaf !== "numbers" || !Array.isArray(parsed.official)) {
        setFileNote(t.numbersBad);
        return;
      }
      const official = [...settings.officialNumbers];
      for (const row of parsed.official) {
        const e164 = normalizePhone(row.e164 || "");
        if (!e164) continue;
        const next = { id: e164, label: String(row.label || e164).slice(0, 80), e164 };
        const at = official.findIndex((item) => item.e164 === e164);
        if (at >= 0) official[at] = next;
        else official.unshift(next);
      }
      const blocked = [...settings.blockedNumbers];
      for (const raw of parsed.blocked || []) {
        const e164 = normalizePhone(raw);
        if (e164 && !blocked.includes(e164)) blocked.unshift(e164);
      }
      void saveSettings({ ...settings, officialNumbers: official, blockedNumbers: blocked });
      setFileNote(t.numbersImported);
    } catch {
      setFileNote(t.numbersBad);
    }
  }

  function parsed() {
    const e164 = normalizePhone(number);
    if (!e164) {
      setBad(true);
      return null;
    }
    setBad(false);
    return e164;
  }

  return (
    <Frame>
      <TopBar title={t.numbersTitle} />
      <p className="mb-3 text-sm leading-relaxed text-muted">{t.numbersLead}</p>
      <input value={label} onChange={(event) => setLabel(event.target.value)} placeholder={t.numberLabel} className="mb-2 h-10 w-full rounded-xl border border-line bg-ink-2 px-3 text-sm" />
      <input value={number} onChange={(event) => setNumber(event.target.value)} inputMode="tel" placeholder="+968" className="h-10 w-full rounded-xl border border-line bg-ink-2 px-3 text-sm" />
      {bad ? <p className="mt-2 text-sm text-gold">{t.numberBad}</p> : null}
      <div className="mt-2 grid grid-cols-2 gap-2">
        <button
          type="button"
          className="h-10 rounded-xl bg-teal text-sm font-semibold text-teal-ink"
          onClick={() => {
            const e164 = parsed();
            if (!e164) return;
            const row = { id: e164, label: label.trim() || e164, e164 };
            void saveSettings({
              ...settings,
              officialNumbers: [row, ...settings.officialNumbers.filter((item) => item.e164 !== e164)],
            });
            setNumber("");
            setLabel("");
          }}
        >
          {t.numberAdd}
        </button>
        <button
          type="button"
          className="h-10 rounded-xl border border-line text-sm font-medium"
          onClick={() => {
            const e164 = parsed();
            if (!e164) return;
            void saveSettings({
              ...settings,
              blockedNumbers: [e164, ...settings.blockedNumbers.filter((item) => item !== e164)],
            });
            setNumber("");
          }}
        >
          {t.blockAdd}
        </button>
      </div>
      <div className="mt-2 grid grid-cols-2 gap-2">
        <button
          type="button"
          className="h-10 rounded-xl border border-line text-sm font-medium"
          onClick={() => {
            const body = JSON.stringify({ kanaf: "numbers", official: settings.officialNumbers, blocked: settings.blockedNumbers });
            const native = (window as Window & { KanafNative?: { saveText?: (name: string, body: string) => string } }).KanafNative;
            if (native?.saveText) {
              setFileNote(native.saveText("kanaf-numbers.json", body) === "ok" ? t.exported : t.failed);
              return;
            }
            const blob = new Blob([body], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = "kanaf-numbers.json";
            link.click();
            URL.revokeObjectURL(url);
            setFileNote(t.exported);
          }}
        >
          {t.numbersExport}
        </button>
        <button
          type="button"
          className="h-10 rounded-xl border border-line text-sm font-medium"
          onClick={() => {
            const native = (window as Window & { KanafNative?: { pickNumbers?: () => void } }).KanafNative;
            if (!native?.pickNumbers || shell !== "android") {
              const input = document.createElement("input");
              input.type = "file";
              input.accept = "application/json,text/plain";
              input.onchange = () => {
                const file = input.files?.[0];
                if (!file) return;
                void file.text().then(mergeBook);
              };
              input.click();
              return;
            }
            (window as Window & { __kanafNumbers?: (text: string) => void }).__kanafNumbers = (text) => {
              if (!text) return;
              mergeBook(text);
            };
            native.pickNumbers();
          }}
        >
          {t.numbersImport}
        </button>
      </div>
      {fileNote ? <p className="mt-2 text-sm text-teal">{fileNote}</p> : null}
      <ul className="mt-3 space-y-2">
        {settings.officialNumbers.map((row) => (
          <li key={row.id} className="glass flex items-center gap-2 p-3 text-sm">
            <span className="min-w-0 flex-1">
              <span className="block font-medium">{row.label}</span>
              <Bidi>{row.e164}</Bidi>
            </span>
            <button
              type="button"
              className="text-gold"
              onClick={() => void saveSettings({ ...settings, officialNumbers: settings.officialNumbers.filter((item) => item.id !== row.id) })}
            >
              {t.numberRemove}
            </button>
          </li>
        ))}
        {settings.blockedNumbers.map((e164) => (
          <li key={e164} className="glass flex items-center gap-2 p-3 text-sm">
            <span className="min-w-0 flex-1 text-gold">
              <Bidi>{e164}</Bidi>
            </span>
            <button
              type="button"
              className="text-gold"
              onClick={() => void saveSettings({ ...settings, blockedNumbers: settings.blockedNumbers.filter((item) => item !== e164) })}
            >
              {t.numberRemove}
            </button>
          </li>
        ))}
      </ul>
      <section className="mt-4">
        <h2 className="text-sm font-semibold">{t.callTitle}</h2>
        <p className="mt-1 text-sm leading-relaxed text-muted">{t.callLead}</p>
        <button
          type="button"
          className="mt-2 h-10 w-full rounded-xl border border-line text-sm font-medium"
          onClick={() => {
            const native = (window as Window & { KanafNative?: { callRole?: () => string; askCallRole?: () => void } }).KanafNative;
            if (!native?.callRole || shell !== "android") {
              setRole(t.cleanWeb);
              return;
            }
            const state = native.callRole();
            if (state === "old") setRole(t.callOld);
            else if (state === "held") setRole(t.callOn);
            else if (state === "missing") setRole(t.callOff);
            else native.askCallRole?.();
          }}
        >
          {t.callAsk}
        </button>
        {role ? <p className="mt-2 text-sm text-teal">{role}</p> : null}
      </section>
    </Frame>
  );
}
