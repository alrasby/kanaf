import { createFileRoute, Link } from "@tanstack/react-router";
import { Bidi, Frame, TopBar } from "@/components/kanaf/chrome";
import { useI18n } from "@/lib/kanaf/i18n";
import { useKanaf } from "@/lib/kanaf/store";
import type { CheckedFile } from "@/lib/kanaf/types";

export const Route = createFileRoute("/checked")({ component: Checked });

const kindKey: Record<CheckedFile["kind"], "kindApk" | "kindZip" | "kindOffice" | "kindImage" | "kindPdf" | "kindRar" | "kindOle" | "kindOther"> = {
  apk: "kindApk",
  zip: "kindZip",
  office: "kindOffice",
  image: "kindImage",
  pdf: "kindPdf",
  rar: "kindRar",
  ole: "kindOle",
  other: "kindOther",
};

function Checked() {
  const { t } = useI18n();
  const rows = useKanaf((s) => s.checked);
  const hits = rows.some((row) => row.verdict === "malicious" || row.verdict === "suspicious");
  return (
    <Frame>
      <TopBar title={t.fileReport} />
      <p className="mb-3 text-sm leading-relaxed text-muted">{t.fileLead}</p>
      {rows.length === 0 ? <p className="text-sm text-muted">{t.fileSkipped}</p> : null}
      <ul className="space-y-2">
        {rows.map((row) => (
          <li key={`${row.name}-${row.sha256}`} className="glass p-3 text-sm">
            <p className={row.verdict === "clean" ? "font-semibold text-teal" : "font-semibold text-gold"}>
              {row.verdict === "malicious" ? t.malicious : row.verdict === "suspicious" ? t.suspicious : row.verdict === "skipped" ? t.fileSkipped : t.fileClean}
            </p>
            <p className="mt-1">
              <Bidi>{row.name}</Bidi>
            </p>
            <p className="mt-1 text-muted">{t[kindKey[row.kind]]}</p>
          </li>
        ))}
      </ul>
      {hits ? (
        <Link to="/results" className="mt-3 flex h-10 items-center justify-center rounded-xl bg-gold/15 text-sm font-semibold text-gold">
          {t.results}
        </Link>
      ) : null}
    </Frame>
  );
}
