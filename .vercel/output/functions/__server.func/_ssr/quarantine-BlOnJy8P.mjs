import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { A as revokeAllow, C as purgeVault, V as useKanaf, Z as useI18n, c as Frame, d as TopBar, k as restoreVault, o as Bidi, s as Confirm } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/quarantine-BlOnJy8P.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function Quarantine() {
	const { t } = useI18n();
	const vault = useKanaf((s) => s.vault);
	const allow = useKanaf((s) => s.allow);
	const [ask, setAsk] = (0, import_react.useState)(null);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.quarantineTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm text-muted",
			children: t.vaultHelp
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
			className: "text-sm font-semibold text-gold",
			children: t.vault
		}),
		vault.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-muted",
			children: t.emptyVault
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "mt-2 space-y-3",
			children: vault.map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass p-4",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "font-medium",
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: item.name })
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "mt-3 flex gap-2",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						className: "min-h-12 flex-1 rounded-2xl bg-teal text-sm font-semibold text-teal-ink",
						onClick: () => setAsk({
							id: item.id,
							kind: "restore"
						}),
						children: t.restore
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						className: "min-h-12 flex-1 rounded-2xl bg-danger text-sm",
						onClick: () => setAsk({
							id: item.id,
							kind: "purge"
						}),
						children: t.purge
					})]
				})]
			}, item.id))
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
			className: "mt-6 text-sm font-semibold text-gold",
			children: t.allowed
		}),
		allow.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-muted",
			children: t.emptyAllow
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "mt-2 space-y-3",
			children: allow.map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass flex items-center justify-between gap-3 p-4",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: item.name }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "min-h-12 shrink-0 rounded-2xl border border-line px-3 text-sm",
					onClick: () => void revokeAllow(item.id),
					children: t.revoke
				})]
			}, item.id))
		}),
		ask ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Confirm, {
			title: ask.kind === "purge" ? t.purge : t.restore,
			body: ask.kind === "purge" ? t.confirmPurge : t.confirmRestore,
			confirm: ask.kind === "purge" ? t.yesDelete : t.restore,
			danger: ask.kind === "purge",
			onClose: () => setAsk(null),
			onConfirm: () => {
				if (ask.kind === "purge") purgeVault(ask.id);
				else restoreVault(ask.id);
				setAsk(null);
			}
		}) : null
	] });
}
//#endregion
export { Quarantine as component };
