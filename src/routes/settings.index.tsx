import { createFileRoute, Link } from "@tanstack/react-router";
import { Frame, TopBar } from "@/components/kanaf/chrome";
import { useI18n } from "@/lib/kanaf/i18n";

export const Route = createFileRoute("/settings/")({ component: SettingsHome });

const links = [
  { to: "/settings/schedule", key: "schedule" },
  { to: "/settings/folders", key: "folders" },
  { to: "/settings/sources", key: "sources" },
  { to: "/settings/numbers", key: "numbersTitle" },
  { to: "/settings/clean", key: "cleanTitle" },
  { to: "/settings/device", key: "deviceTitle" },
  { to: "/settings/log", key: "log" },
  { to: "/settings/network", key: "network" },
  { to: "/quarantine", key: "quarantineTitle" },
  { to: "/privacy", key: "privacy" },
] as const;

function SettingsHome() {
  const { t } = useI18n();
  return (
    <Frame>
      <TopBar title={t.settingsTitle} />
      <ul className="flex flex-col gap-3">
        {links.map((item) => (
          <li key={item.to}>
            <Link to={item.to} className="glass flex min-h-14 items-center px-4 text-sm font-medium">
              {t[item.key]}
            </Link>
          </li>
        ))}
      </ul>
    </Frame>
  );
}
