import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { V as useKanaf, Z as useI18n, c as Frame, d as TopBar } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/settings.clean-B0xrGWDt.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function bridge() {
	return window.KanafNative;
}
function sizeLabel(size) {
	if (!Number.isFinite(size) || size < 0) return "";
	if (size >= 1e9) return `${(size / 1e9).toFixed(1)} GB`;
	if (size >= 1e6) return `${Math.round(size / 1e6)} MB`;
	if (size >= 1e3) return `${Math.round(size / 1e3)} KB`;
	return `${size} B`;
}
function Clean() {
	const { t } = useI18n();
	const shell = useKanaf((s) => s.shell);
	const [note, setNote] = (0, import_react.useState)("");
	const [rows, setRows] = (0, import_react.useState)([]);
	const [apps, setApps] = (0, import_react.useState)([]);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.cleanTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm leading-relaxed text-muted",
			children: t.cleanLead
		}),
		shell !== "android" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm text-muted",
			children: t.cleanWeb
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "flex flex-col gap-2",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "h-11 w-full rounded-xl bg-teal text-sm font-semibold text-teal-ink",
				onClick: () => {
					const native = bridge();
					if (!native?.askClearAppCache || shell !== "android") {
						setNote(t.cleanWeb);
						return;
					}
					if (native.askClearAppCache() === "ok") {
						setApps([]);
						setNote(t.cleanAppsNote);
						return;
					}
					try {
						const parsed = JSON.parse(native.listUserApps?.() || "[]");
						setApps(Array.isArray(parsed) ? parsed : []);
					} catch {
						setApps([]);
					}
					setNote(t.cleanAppsFail);
				},
				children: t.cleanApps
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "h-11 w-full rounded-xl border border-line bg-ink-2 text-sm font-medium",
				onClick: () => {
					const native = bridge();
					if (!native?.clearOwnCache || shell !== "android") {
						setNote(t.cleanWeb);
						return;
					}
					native.clearOwnCache();
					setApps([]);
					if (native.filesAccess?.() === "need") {
						native.askFilesAccess?.();
						setRows([]);
						setNote(t.cleanNeedFiles);
						return;
					}
					try {
						const parsed = JSON.parse(native.listJunk?.() || "[]");
						setRows(Array.isArray(parsed) ? parsed : []);
						setNote(parsed.length ? t.cleanFreed : `${t.cleanFreed} ${t.cleanNone}`);
					} catch {
						setRows([]);
						setNote(t.cleanFreed);
					}
				},
				children: t.cleanTemp
			})]
		}),
		note ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-3 text-sm text-teal",
			children: note
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("ul", {
			className: "mt-3 space-y-2",
			children: [apps.map((app) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass flex items-center gap-2 p-3 text-sm",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
					className: "min-w-0 flex-1 truncate",
					dir: "auto",
					children: app.name
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "text-gold",
					onClick: () => bridge()?.openAppInfo?.(app.pkg),
					children: t.cleanOpen
				})]
			}, app.pkg)), rows.map((row) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass flex items-center gap-2 p-3 text-sm",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
					className: "min-w-0 flex-1",
					dir: "ltr",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: "block truncate text-left",
						children: row.name
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: "mt-0.5 block text-left text-xs text-muted",
						children: sizeLabel(row.size)
					})]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "text-gold",
					onClick: () => {
						bridge()?.deleteJunk?.(JSON.stringify([row.id]));
						setRows((current) => current.filter((item) => item.id !== row.id));
					},
					children: t.cleanDelete
				})]
			}, row.id))]
		})
	] });
}
//#endregion
export { Clean as component };
