import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { D as rememberUrl, L as scanLink, V as useKanaf, Z as useI18n, a as Route$18, c as Frame, d as TopBar, o as Bidi, s as Confirm, z as tryRedirect } from "./router-CrxcCbvj.mjs";
import { t as reasonLines } from "./reasons-CVaRkdUl.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/link-DREBrQFv.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function LinkScan() {
	const { url } = Route$18.useSearch();
	const { t } = useI18n();
	const ready = useKanaf((s) => s.dbStatus === "ready");
	const [result, setResult] = (0, import_react.useState)(null);
	const [open, setOpen] = (0, import_react.useState)(false);
	const [expandNote, setExpandNote] = (0, import_react.useState)("");
	(0, import_react.useEffect)(() => {
		if (!ready || !url) return;
		scanLink(url).then(setResult);
	}, [ready, url]);
	const label = result?.verdict === "malicious" ? t.malicious : result?.verdict === "suspicious" ? t.suspicious : t.noIndicators;
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.linkTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "glass p-4 text-sm",
			children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: url })
		}),
		!result ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-3 text-sm text-muted",
			children: ready ? t.working : t.notReady
		}) : null,
		result ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
			className: "glass mt-3 p-4",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: result.verdict === "clean" ? "text-teal" : "text-gold",
					children: label
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("ul", {
					className: "mt-2 space-y-2 text-sm",
					children: [result.reasons.map((reason) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: reasonLines(t, reason, result.host)[0]?.text }, reason)), result.reasons.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: t.noIndicators }) : null]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "mt-4 flex flex-col gap-3",
					children: [
						result.verdict !== "clean" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
							type: "button",
							className: "min-h-12 rounded-2xl bg-teal font-semibold text-teal-ink",
							onClick: () => void rememberUrl(result.normalized),
							children: t.allowAddress
						}) : null,
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
							type: "button",
							className: "min-h-12 rounded-2xl border border-line",
							onClick: () => setOpen(true),
							children: t.open
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
							type: "button",
							className: "min-h-12 rounded-2xl border border-gold text-sm text-gold",
							onClick: () => {
								setExpandNote(t.expandWarn);
								tryRedirect(result.normalized).then((step) => {
									setExpandNote(step.ok && step.final ? step.final : t.expandFail);
								});
							},
							children: t.expand
						}),
						expandNote ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-sm text-muted",
							children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: expandNote })
						}) : null
					]
				})
			]
		}) : null,
		open && result ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Confirm, {
			title: t.open,
			body: t.confirmOpen,
			confirm: t.open,
			onClose: () => setOpen(false),
			onConfirm: () => {
				window.open(result.normalized, "_blank", "noopener,noreferrer");
				setOpen(false);
			}
		}) : null
	] });
}
//#endregion
export { LinkScan as component };
