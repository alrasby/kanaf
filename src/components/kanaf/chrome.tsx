import { Link } from "@tanstack/react-router";
import { useEffect, useId, type ReactNode } from "react";
import { signatureLabel, useI18n } from "@/lib/kanaf/i18n";
import { boot } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export function Boot() {
  useEffect(() => {
    void boot();
  }, []);
  return null;
}

export function Shield({ large = false }: { large?: boolean }) {
  const id = useId().replace(/:/g, "");
  const { t } = useI18n();
  return (
    <svg viewBox="0 0 120 140" className={large ? "h-12 w-10 shrink-0" : "h-8 w-7"} role="img" aria-label={t.ariaShield}>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#1a3d5c" />
          <stop offset="100%" stopColor="#07111f" />
        </linearGradient>
      </defs>
      <path
        d="M60 6 108 28v40c0 32-20 54-48 66C32 122 12 100 12 68V28Z"
        fill={`url(#${id})`}
        stroke="#E7C27A"
        strokeOpacity="0.45"
        strokeWidth="2"
      />
      <path className={large ? "shield-k" : undefined} d="M46 46h10v16l14-16h13L63 70l22 26H72L58 76v20H46Z" fill="#5CE1FF" />
    </svg>
  );
}

export function Frame({ children }: { children: ReactNode }) {
  return <div className="mx-auto min-h-screen w-full max-w-md px-4 pb-10 pt-4">{children}</div>;
}

export function TopBar({ title }: { title: string }) {
  const { t } = useI18n();
  return (
    <header className="mb-5 flex min-h-12 items-center gap-2">
      <Link to="/" className="inline-flex h-10 shrink-0 items-center justify-center rounded-full px-2 text-sm font-medium text-gold">
        {t.back}
      </Link>
      <h1 className="min-w-0 flex-1 truncate text-center text-base font-semibold">{title}</h1>
      <span className="shrink-0">
        <Shield />
      </span>
    </header>
  );
}

export function HomeBar() {
  const { t, toggle, locale } = useI18n();
  const count = useKanaf((s) => s.hashCount);
  const ready = useKanaf((s) => s.dbStatus === "ready");
  return (
    <header className="mb-4 flex items-center gap-3">
      <Shield large />
      <div className="min-w-0 flex-1">
        <h1 className="text-lg font-semibold leading-none">{t.name}</h1>
        <p className="mt-1 text-xs leading-snug text-muted">{t.tagline}</p>
        {ready ? <p className="mt-1 text-[11px] text-cyan">{signatureLabel(locale, count)}</p> : null}
      </div>
      <button
        type="button"
        onClick={toggle}
        className="inline-flex h-8 shrink-0 items-center justify-center rounded-full border border-line px-3 text-xs font-semibold text-gold"
      >
        {t.lang}
      </button>
    </header>
  );
}

export function Notice() {
  const notice = useKanaf((s) => s.notice);
  const { t } = useI18n();
  if (!notice) return null;
  const namedFail = notice.startsWith("update-fail:");
  const map: Record<string, string> = {
    grant: t.grant,
    nothing: t.nothing,
    allowed: t.allowedDone,
    moved: t.moved,
    remains: t.originalRemains,
    "delete-blocked": t.deleteBlocked,
    deleted: t.yesDelete,
    cellular: t.cellularBlocked,
    "update-fail": t.updateFail,
    "update-ok": t.updateOk,
    charging: t.chargingSkip,
    uninstall: t.uninstallAsked,
    repacked: t.integrityBad,
  };
  return (
    <p className="glass mb-3 px-4 py-3 text-sm text-fg" role="status">
      {namedFail ? `${t.updateFail} ${notice.slice("update-fail:".length)}` : (map[notice] ?? notice)}
    </p>
  );
}

export function Confirm({
  title,
  body,
  confirm,
  danger,
  onConfirm,
  onClose,
}: {
  title: string;
  body: string;
  confirm: string;
  danger?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const { t } = useI18n();
  return (
    <div className="fixed inset-0 z-20 flex items-end justify-center bg-ink/70 p-4 sm:items-center" role="presentation">
      <div role="dialog" aria-modal="true" aria-labelledby="confirm-title" className="glass w-full max-w-md p-5">
        <h2 id="confirm-title" className="text-lg font-semibold">
          {title}
        </h2>
        <p className="mt-2 text-sm leading-relaxed text-muted">{body}</p>
        <div className="mt-5 flex gap-3">
          <button type="button" onClick={onClose} className="min-h-12 flex-1 rounded-2xl border border-line text-sm">
            {t.close}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className={
              danger
                ? "min-h-12 flex-1 rounded-2xl bg-danger text-sm font-semibold text-fg"
                : "min-h-12 flex-1 rounded-2xl bg-teal text-sm font-semibold text-teal-ink"
            }
          >
            {confirm}
          </button>
        </div>
      </div>
    </div>
  );
}

export function Bidi({ children }: { children: ReactNode }) {
  return <bdi className="break-all font-medium text-cyan">{children}</bdi>;
}
