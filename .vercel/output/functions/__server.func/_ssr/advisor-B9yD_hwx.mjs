import { S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { K as adviceLabel, S as openDeviceSettings, V as useKanaf, Z as useI18n, c as Frame, d as TopBar } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/advisor-B9yD_hwx.js
var import_jsx_runtime = require_jsx_runtime();
function Advisor() {
	const { t, locale } = useI18n();
	const sources = useKanaf((s) => s.sources);
	const findings = useKanaf((s) => s.findings.length);
	const realtime = useKanaf((s) => s.realtime);
	const dbStatus = useKanaf((s) => s.dbStatus);
	const shell = useKanaf((s) => s.shell);
	const device = useKanaf((s) => s.device);
	const stale = sources.some((source) => {
		const time = Date.parse(source.updatedAt);
		return Number.isFinite(time) && Date.now() - time > 6048e5;
	});
	const notify = typeof Notification !== "undefined" ? Notification.permission : "default";
	const insecure = shell !== "android" && typeof window !== "undefined" && !window.isSecureContext;
	const tips = [
		stale || dbStatus !== "ready" ? t.advisorStale : null,
		findings > 0 ? t.advisorPending : null,
		!realtime ? t.advisorLive : null,
		notify === "denied" ? t.advisorNotify : null,
		insecure ? t.advisorInsecure : null
	].filter((tip) => Boolean(tip));
	const rows = shell === "android" && device ? [
		{
			label: t.lock,
			value: device.lock ? t.lockOn : t.lockOff,
			bad: !device.lock
		},
		{
			label: t.patch,
			value: device.patch || t.off,
			bad: false
		},
		{
			label: t.usb,
			value: device.usb ? t.usbOn : t.usbOff,
			bad: device.usb
		},
		{
			label: t.developer,
			value: device.developer ? t.devOn : t.devOff,
			bad: device.developer
		}
	] : null;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.advisorTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "text-lg font-semibold",
			children: adviceLabel(locale, tips.length)
		}),
		tips.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-teal",
			children: t.noAdvice
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "mt-3 space-y-2",
			children: tips.map((tip) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", {
				className: "glass px-4 py-3 text-sm",
				children: tip
			}, tip))
		}),
		rows ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
				className: "mt-6 text-sm font-semibold text-gold",
				children: t.deviceLead
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
				className: "mt-2 space-y-2 text-sm",
				children: rows.map((row) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
					className: "glass px-4 py-3",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-muted",
						children: row.label
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: row.bad ? "mt-1 text-gold" : "mt-1 text-teal",
						children: row.value
					})]
				}, row.label))
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				onClick: () => openDeviceSettings("security"),
				className: "mt-3 min-h-12 w-full rounded-2xl border border-line text-sm",
				children: t.openSettings
			})
		] }) : /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(import_jsx_runtime.Fragment, { children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
				className: "mt-6 text-sm font-semibold text-gold",
				children: t.unavailable
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "mt-2 text-sm text-muted",
				children: t.unavailableBody
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
				className: "mt-2 space-y-2 text-sm",
				children: [
					t.lock,
					t.patch,
					t.usb,
					t.developer
				].map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", {
					className: "glass px-4 py-3 text-muted",
					children: item
				}, item))
			})
		] }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-4 text-sm text-muted",
			children: t.cannotChange
		})
	] });
}
//#endregion
export { Advisor as component };
