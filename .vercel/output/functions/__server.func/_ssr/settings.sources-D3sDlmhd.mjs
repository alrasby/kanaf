import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { J as formatCount, V as useKanaf, Z as useI18n, c as Frame, d as TopBar, j as runEicar, o as Bidi } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/settings.sources-D3sDlmhd.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function Sources() {
	const { t, locale } = useI18n();
	const sources = useKanaf((s) => s.sources);
	const status = useKanaf((s) => s.dbStatus);
	const [note, setNote] = (0, import_react.useState)("");
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.sourcesTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm leading-relaxed text-muted",
			children: t.cloudHonest
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "space-y-3",
			children: sources.map((source) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass p-4 text-sm",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "font-semibold",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: source.id })
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "mt-1 text-muted",
						children: [
							t.version,
							" ",
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: source.version })
						]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "text-muted",
						children: [
							t.updated,
							" ",
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: source.updatedAt })
						]
					}),
					source.state === "ready" ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [
						t.count,
						" ",
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: formatCount(locale, source.count) })
					] }) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: source.state === "loading" ? t.downloading : source.state === "failed" ? t.failed : t.notLoaded }),
					source.error ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-gold",
						children: source.error
					}) : null,
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-muted",
						children: source.license
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("a", {
						className: "text-teal",
						href: source.terms,
						target: "_blank",
						rel: "noreferrer",
						children: t.sourceTerms
					})
				]
			}, source.id))
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "mt-5",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					className: "text-sm font-semibold",
					children: t.selfTest
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-1 text-sm text-muted",
					children: t.eicarHelp
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					disabled: status !== "ready",
					className: "mt-3 min-h-12 w-full rounded-2xl border border-gold text-gold disabled:opacity-50",
					onClick: () => {
						runEicar().then((hit) => setNote(hit ? t.eicarHit : t.eicarMiss));
					},
					children: t.eicar
				}),
				note ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm",
					children: note
				}) : null
			]
		})
	] });
}
//#endregion
export { Sources as component };
