import { S as require_jsx_runtime, y as Link } from "../_libs/@tanstack/react-router+[...].mjs";
import { V as useKanaf, Z as useI18n, c as Frame, d as TopBar, o as Bidi } from "./router-CrxcCbvj.mjs";
import { t as reasonLines } from "./reasons-CVaRkdUl.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/results-BoQuUELV.js
var import_jsx_runtime = require_jsx_runtime();
function Results() {
	const { t } = useI18n();
	const findings = useKanaf((s) => s.findings);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.resultsTitle }),
		findings.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "text-sm text-muted",
			children: t.emptyResults
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "flex flex-col gap-3",
			children: findings.map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass p-4",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "font-semibold",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: item.name })
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1 text-sm text-muted",
						children: reasonLines(t, item.reasonId, item.detail)[0]?.text
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1 text-xs uppercase tracking-wide text-gold",
						children: item.verdict === "malicious" ? t.malicious : t.suspicious
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
						to: "/decision/$id",
						params: { id: item.id },
						className: "mt-3 inline-flex min-h-12 items-center text-sm font-semibold text-teal",
						children: t.decide
					})
				]
			}, item.id))
		})
	] });
}
//#endregion
export { Results as component };
