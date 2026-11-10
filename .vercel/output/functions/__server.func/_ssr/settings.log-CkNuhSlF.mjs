import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { J as formatCount, M as saveDecisions, V as useKanaf, Z as useI18n, c as Frame, d as TopBar } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/settings.log-CkNuhSlF.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var LINK_REASONS = /* @__PURE__ */ new Set([
	"listed",
	"ip-host",
	"shortener",
	"punycode",
	"lookalike",
	"userinfo",
	"brand-host",
	"doc-link"
]);
var PHONE_REASONS = /* @__PURE__ */ new Set(["premium-rate", "callback-lure"]);
function LogPage() {
	const { t, locale } = useI18n();
	const log = useKanaf((s) => s.log);
	const findings = useKanaf((s) => s.findings);
	const [note, setNote] = (0, import_react.useState)("");
	const weekAgo = Date.now() - 6048e5;
	const week = findings.filter((item) => item.createdAt >= weekAgo);
	const messages = week.filter((item) => item.kind === "message").length;
	const links = week.filter((item) => item.kind === "url" || LINK_REASONS.has(item.reasonId)).length;
	const phones = week.filter((item) => PHONE_REASONS.has(item.reasonId)).length;
	const modes = {
		deep: "modeDeep",
		quick: "modeQuick",
		custom: "modeCustom",
		scheduled: "modeScheduled",
		live: "modeLive"
	};
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.logTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "mb-4 glass p-4 text-sm",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "font-semibold",
					children: t.weekTitle
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "mt-2 text-muted",
					children: [
						t.weekMessages,
						" ",
						formatCount(locale, messages)
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "text-muted",
					children: [
						t.weekLinks,
						" ",
						formatCount(locale, links)
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "text-muted",
					children: [
						t.weekPhones,
						" ",
						formatCount(locale, phones)
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "mt-3 h-10 w-full rounded-xl border border-line text-sm font-medium",
					onClick: () => {
						const text = [
							"Kanaf week",
							(/* @__PURE__ */ new Date()).toISOString(),
							`messages ${messages}`,
							`links ${links}`,
							`phones ${phones}`,
							"",
							...week.map((item) => `${item.kind}\t${item.reasonId}\t${item.name}\t${item.detail}`)
						].join("\n");
						const native = window.KanafNative;
						if (native?.saveText) {
							setNote(native.saveText("kanaf-week.txt", text) === "ok" ? t.exported : t.failed);
							return;
						}
						const blob = new Blob([text], { type: "text/plain" });
						const url = URL.createObjectURL(blob);
						const link = document.createElement("a");
						link.href = url;
						link.download = "kanaf-week.txt";
						link.click();
						URL.revokeObjectURL(url);
						setNote(t.exported);
					},
					children: t.weekExport
				})
			]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
			type: "button",
			className: "mb-3 h-10 w-full rounded-xl border border-line text-sm font-medium",
			onClick: () => {
				saveDecisions().then((result) => setNote(result === "empty" ? t.exportEmpty : result === "fail" ? t.failed : t.exported));
			},
			children: t.exportDecisions
		}),
		note ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm text-teal",
			children: note
		}) : null,
		log.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "text-sm text-muted",
			children: t.logEmpty
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "space-y-3",
			children: log.map((entry) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass p-4 text-sm",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "font-semibold",
						children: t[modes[entry.mode]]
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-muted",
						children: new Date(entry.startedAt).toISOString().slice(0, 16).replace("T", " ")
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", { children: [
						t.files,
						" ",
						formatCount(locale, entry.files),
						" · ",
						t.findings,
						" ",
						formatCount(locale, entry.findings),
						" · ",
						t.skipped,
						" ",
						formatCount(locale, entry.skipped)
					] }),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: entry.status === "done" ? t.statusDone : entry.status === "cancelled" ? t.statusCancelled : t.failed })
				]
			}, entry.id))
		})
	] });
}
//#endregion
export { LogPage as component };
