import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { N as saveSettings, V as useKanaf, Z as useI18n, b as metered, c as Frame, d as TopBar, x as networkKind } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/settings.network-lANJgjF6.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function Network() {
	const { t } = useI18n();
	const settings = useKanaf((s) => s.settings);
	const shell = useKanaf((s) => s.shell);
	const kind = networkKind();
	const line = kind === "wifi" ? t.connectionWifi : kind === "cellular" ? t.connectionCell : kind === "none" ? t.connectionNone : t.connectionUnknown;
	const [access, setAccess] = (0, import_react.useState)("web");
	(0, import_react.useEffect)(() => {
		const read = () => {
			const native = window.KanafNative;
			if (!native?.notices) return;
			setAccess(native.notices() === "on" ? "on" : "off");
		};
		read();
		window.addEventListener("focus", read);
		return () => window.removeEventListener("focus", read);
	}, []);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.networkTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", {
			className: "glass flex min-h-14 items-center justify-between gap-3 px-4 text-sm",
			children: [t.wifiOnly, /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
				type: "checkbox",
				checked: settings.wifiOnly,
				onChange: (event) => void saveSettings({
					...settings,
					wifiOnly: event.target.checked
				})
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", {
			className: "glass mt-3 flex min-h-14 items-center justify-between gap-3 px-4 text-sm",
			children: [t.engineCloud, /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
				type: "checkbox",
				checked: settings.cloudFeeds,
				onChange: (event) => void saveSettings({
					...settings,
					cloudFeeds: event.target.checked
				})
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-3 text-sm leading-relaxed text-muted",
			children: t.cloudHint
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-muted",
			children: line
		}),
		metered() === true ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-gold",
			children: t.cellularWarn
		}) : null,
		shell === "android" ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "mt-4",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					className: "text-sm font-semibold",
					children: t.notices
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm leading-relaxed text-muted",
					children: t.noticesLead
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "mt-2 h-10 w-full rounded-xl border border-line text-sm",
					onClick: () => {
						const native = window.KanafNative;
						native?.openSettings?.("notices");
						setAccess(native?.notices?.() === "on" ? "on" : "off");
					},
					children: t.noticesOpen
				}),
				access !== "web" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm text-muted",
					children: access === "on" ? t.noticesOn : t.noticesOff
				}) : null
			]
		}) : null
	] });
}
//#endregion
export { Network as component };
