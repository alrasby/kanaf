import { createFileRoute } from "@tanstack/react-router";
import { Bidi, Frame, TopBar } from "@/components/kanaf/chrome";
import { useI18n } from "@/lib/kanaf/i18n";
import { removeFolder, watchFolder } from "@/lib/kanaf/session";
import { useKanaf } from "@/lib/kanaf/store";

export const Route = createFileRoute("/settings/folders")({ component: Folders });

function Folders() {
  const { t } = useI18n();
  const folders = useKanaf((s) => s.folders);
  return (
    <Frame>
      <TopBar title={t.foldersTitle} />
      {folders.length === 0 ? <p className="text-sm text-muted">{t.foldersEmpty}</p> : null}
      <ul className="space-y-2">
        {folders.map((folder) => (
          <li key={folder.id} className="glass flex items-center justify-between px-4 py-3">
            <Bidi>{folder.name}</Bidi>
            <button type="button" className="min-h-12 text-sm text-gold" onClick={() => void removeFolder(folder.id)}>
              {t.removeFolder}
            </button>
          </li>
        ))}
      </ul>
      <button type="button" className="mt-4 min-h-12 w-full rounded-2xl bg-teal font-semibold text-teal-ink" onClick={() => void watchFolder()}>
        {t.addFolder}
      </button>
    </Frame>
  );
}
