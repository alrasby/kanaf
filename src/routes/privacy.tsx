import { createFileRoute } from "@tanstack/react-router";
import { Frame, TopBar } from "@/components/kanaf/chrome";
import { useI18n } from "@/lib/kanaf/i18n";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/privacy")({ component: Privacy });

function Privacy() {
  const { t } = useI18n();
  const shell = useKanaf((s) => s.shell);
  const paragraphs = [t.privacy1, t.privacy2, shell === "android" ? t.privacyApp : t.privacy3, t.privacy4];
  return (
    <Frame>
      <TopBar title={t.privacyTitle} />
      <div className="space-y-3 text-sm leading-relaxed">
        {paragraphs.map((paragraph) => (
          <p key={paragraph} className="glass px-4 py-3">
            {paragraph}
          </p>
        ))}
      </div>
      <h2 className="mb-2 mt-5 text-sm font-semibold">{t.limitsTitle}</h2>
      <ul className="space-y-3">
        {(shell === "android"
          ? [t.limitApp1, t.limitApp2, t.limit3, t.limit4, t.limitApp5, t.limit6, t.limit7]
          : [t.limit1, t.limit2, t.limit3, t.limit4, t.limit5, t.limit6, t.limit7]
        ).map((item) => (
          <li key={item} className="glass px-4 py-3 text-sm leading-relaxed">
            {item}
          </li>
        ))}
      </ul>
    </Frame>
  );
}
