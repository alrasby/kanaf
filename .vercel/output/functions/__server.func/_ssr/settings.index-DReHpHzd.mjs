import { S as require_jsx_runtime, y as Link } from "../_libs/@tanstack/react-router+[...].mjs";
import { Z as useI18n, c as Frame, d as TopBar } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/settings.index-DReHpHzd.js
var import_jsx_runtime = require_jsx_runtime();
var links = [
	{
		to: "/settings/schedule",
		key: "schedule"
	},
	{
		to: "/settings/folders",
		key: "folders"
	},
	{
		to: "/settings/sources",
		key: "sources"
	},
	{
		to: "/settings/numbers",
		key: "numbersTitle"
	},
	{
		to: "/settings/clean",
		key: "cleanTitle"
	},
	{
		to: "/settings/device",
		key: "deviceTitle"
	},
	{
		to: "/settings/log",
		key: "log"
	},
	{
		to: "/settings/network",
		key: "network"
	},
	{
		to: "/quarantine",
		key: "quarantineTitle"
	},
	{
		to: "/privacy",
		key: "privacy"
	}
];
function SettingsHome() {
	const { t } = useI18n();
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.settingsTitle }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
		className: "flex flex-col gap-3",
		children: links.map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
			to: item.to,
			className: "glass flex min-h-14 items-center px-4 text-sm font-medium",
			children: t[item.key]
		}) }, item.to))
	})] });
}
//#endregion
export { SettingsHome as component };
