import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime, b as useNavigate } from "../_libs/@tanstack/react-router+[...].mjs";
import { J as formatCount, V as useKanaf, Z as useI18n, _ as deleteFinding, c as Frame, d as TopBar, f as allowFinding, n as Route$9, o as Bidi, s as Confirm, w as quarantineFinding } from "./router-CrxcCbvj.mjs";
import { t as reasonLines } from "./reasons-CVaRkdUl.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/decision._id-WbkQcoYZ.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function Decision() {
	const { id } = Route$9.useParams();
	const { t, locale } = useI18n();
	const navigate = useNavigate();
	const finding = useKanaf((s) => s.findings.find((item) => item.id === id));
	const [ask, setAsk] = (0, import_react.useState)(null);
	if (!finding) return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.decisionTitle }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
		className: "text-sm text-muted",
		children: t.emptyResults
	})] });
	const lines = reasonLines(t, finding.reasonId, finding.detail);
	const file = finding.kind === "file";
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.decisionTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
			className: "glass p-4",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					className: "text-lg font-semibold",
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: finding.name })
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-1 text-xs text-gold",
					children: finding.verdict === "malicious" ? t.malicious : t.suspicious
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
					className: "mt-4 text-sm text-muted",
					children: t.reason
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
					className: "mt-1 space-y-2 text-sm leading-relaxed",
					children: lines.map((line) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", { children: [
						line.text,
						" ",
						line.detail ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: line.detail }) : null
					] }, line.text))
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
					className: "mt-4 text-sm text-muted",
					children: t.permissions
				}),
				finding.permissions.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "text-sm",
					children: t.noPerms
				}) : null,
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
					className: "mt-1 space-y-1 text-sm",
					children: finding.permissions.map((perm) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: perm }) }, perm))
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "mt-3 text-xs text-muted",
					children: [
						t.bytes,
						" ",
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: formatCount(locale, finding.size) })
					]
				}),
				finding.kind === "url" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-3 text-sm text-muted",
					children: t.linkNoVault
				}) : null,
				finding.kind === "message" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-3 text-sm text-muted",
					children: t.messageNoDelete
				}) : null
			]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "mt-4 flex flex-col gap-3",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "min-h-12 rounded-2xl bg-teal font-semibold text-teal-ink",
					onClick: () => {
						allowFinding(finding.id).then(() => navigate({ to: "/results" }));
					},
					children: finding.kind === "url" ? t.allowAddress : t.allow
				}),
				file ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "min-h-12 rounded-2xl border border-gold text-gold",
					onClick: () => setAsk("vault"),
					children: t.quarantine
				}) : null,
				file ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "min-h-12 rounded-2xl bg-danger font-semibold",
					onClick: () => setAsk("delete"),
					children: t.delete
				}) : null
			]
		}),
		ask === "delete" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Confirm, {
			title: t.delete,
			body: t.confirmDelete,
			confirm: t.yesDelete,
			danger: true,
			onClose: () => setAsk(null),
			onConfirm: () => {
				deleteFinding(finding.id).then((ok) => {
					setAsk(null);
					if (ok) navigate({ to: "/results" });
				});
			}
		}) : null,
		ask === "vault" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Confirm, {
			title: t.quarantine,
			body: t.confirmVault,
			confirm: t.confirm,
			onClose: () => setAsk(null),
			onConfirm: () => {
				quarantineFinding(finding.id).then(() => navigate({ to: "/results" }));
			}
		}) : null
	] });
}
//#endregion
export { Decision as component };
