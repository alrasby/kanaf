import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { P as scanBehavior, V as useKanaf, Z as useI18n, c as Frame, d as TopBar, o as Bidi, q as behaviorResult } from "./router-CrxcCbvj.mjs";
import { t as reasonLines } from "./reasons-CVaRkdUl.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/behavior-B5tqXg0t.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function Behavior() {
	const { t, locale } = useI18n();
	const ready = useKanaf((s) => s.dbStatus === "ready");
	const shell = useKanaf((s) => s.shell);
	const findings = useKanaf((s) => s.findings).filter((item) => item.reasonId === "heuristic");
	const [running, setRunning] = (0, import_react.useState)(false);
	const [note, setNote] = (0, import_react.useState)("");
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.engineBehavior }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm leading-relaxed text-muted",
			children: t.behaviorLead
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
			type: "button",
			disabled: !ready || running || shell !== "android",
			className: "h-10 w-full rounded-xl bg-teal text-sm font-semibold text-teal-ink disabled:opacity-50",
			onClick: () => {
				setRunning(true);
				setNote("");
				scanBehavior().then((result) => {
					if (result === "web") setNote(t.behaviorWeb);
					else if (result === "fail") setNote(t.behaviorFail);
					else setNote(behaviorResult(locale, result.scanned, result.hits));
				}).catch(() => setNote(t.behaviorFail)).finally(() => setRunning(false));
			},
			children: running ? t.working : t.behaviorScan
		}),
		shell !== "android" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-muted",
			children: t.behaviorWeb
		}) : null,
		note ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: `mt-2 text-sm ${note === t.behaviorFail ? "text-gold" : "text-teal"}`,
			children: note
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "mt-3 space-y-2",
			children: findings.map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass p-3 text-sm",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "font-semibold text-gold",
						children: t.suspicious
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: item.name })
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
						className: "mt-1 space-y-1 text-muted",
						children: reasonLines(t, item.reasonId, item.detail || "").map((line, index) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: line.text }, `${item.id}-${index}`))
					})
				]
			}, item.id))
		})
	] });
}
//#endregion
export { Behavior as component };
