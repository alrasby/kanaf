import { S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { N as saveSettings, V as useKanaf, Z as useI18n, c as Frame, d as TopBar } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/settings.schedule-BOMyDDU0.js
var import_jsx_runtime = require_jsx_runtime();
function Schedule() {
	const { t } = useI18n();
	const settings = useKanaf((s) => s.settings);
	const shell = useKanaf((s) => s.shell);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.scheduleTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-4 text-sm text-muted",
			children: shell === "android" ? t.limitApp5 : t.scheduleHelp
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", {
			className: "glass flex min-h-14 items-center justify-between px-4 text-sm",
			children: [t.enable, /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
				type: "checkbox",
				checked: settings.scheduleEnabled,
				onChange: (event) => void saveSettings({
					...settings,
					scheduleEnabled: event.target.checked
				})
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "mt-3 grid grid-cols-2 gap-2",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: `min-h-12 rounded-2xl border ${settings.every === "day" ? "border-teal text-teal" : "border-line"}`,
				onClick: () => void saveSettings({
					...settings,
					every: "day"
				}),
				children: t.daily
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: `min-h-12 rounded-2xl border ${settings.every === "week" ? "border-teal text-teal" : "border-line"}`,
				onClick: () => void saveSettings({
					...settings,
					every: "week"
				}),
				children: t.weekly
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", {
			className: "glass mt-3 flex min-h-14 items-center justify-between px-4 text-sm",
			children: [t.charging, /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
				type: "checkbox",
				checked: settings.chargingOnly,
				onChange: (event) => void saveSettings({
					...settings,
					chargingOnly: event.target.checked
				})
			})]
		})
	] });
}
//#endregion
export { Schedule as component };
