import { S as require_jsx_runtime, y as Link } from "../_libs/@tanstack/react-router+[...].mjs";
import { V as useKanaf, Z as useI18n, c as Frame, d as TopBar, o as Bidi } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/checked-DQgCsZhy.js
var import_jsx_runtime = require_jsx_runtime();
var kindKey = {
	apk: "kindApk",
	zip: "kindZip",
	office: "kindOffice",
	image: "kindImage",
	pdf: "kindPdf",
	rar: "kindRar",
	ole: "kindOle",
	other: "kindOther"
};
function Checked() {
	const { t } = useI18n();
	const rows = useKanaf((s) => s.checked);
	const hits = rows.some((row) => row.verdict === "malicious" || row.verdict === "suspicious");
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.fileReport }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm leading-relaxed text-muted",
			children: t.fileLead
		}),
		rows.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "text-sm text-muted",
			children: t.fileSkipped
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "space-y-2",
			children: rows.map((row) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass p-3 text-sm",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: row.verdict === "clean" ? "font-semibold text-teal" : "font-semibold text-gold",
						children: row.verdict === "malicious" ? t.malicious : row.verdict === "suspicious" ? t.suspicious : row.verdict === "skipped" ? t.fileSkipped : t.fileClean
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: row.name })
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1 text-muted",
						children: t[kindKey[row.kind]]
					})
				]
			}, `${row.name}-${row.sha256}`))
		}),
		hits ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
			to: "/results",
			className: "mt-3 flex h-10 items-center justify-center rounded-xl bg-gold/15 text-sm font-semibold text-gold",
			children: t.results
		}) : null
	] });
}
//#endregion
export { Checked as component };
