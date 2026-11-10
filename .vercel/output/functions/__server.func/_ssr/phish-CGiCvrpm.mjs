import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { H as extractUrls, L as scanLink, T as readClipboard, U as normalizeUrl, V as useKanaf, W as analyzePhones, Z as useI18n, c as Frame, d as TopBar, o as Bidi, r as Route$16 } from "./router-CrxcCbvj.mjs";
import { t as reasonLines } from "./reasons-CVaRkdUl.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/phish-CGiCvrpm.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function targetsFrom(raw) {
	const found = extractUrls(raw);
	if (found.length) return found;
	const one = normalizeUrl(raw);
	return one ? [one.href] : [];
}
function Phish() {
	const { text } = Route$16.useSearch();
	const { t } = useI18n();
	const official = useKanaf((s) => s.settings.officialNumbers);
	const ready = useKanaf((s) => s.dbStatus === "ready");
	const [draft, setDraft] = (0, import_react.useState)(text);
	const [rows, setRows] = (0, import_react.useState)([]);
	const [phones, setPhones] = (0, import_react.useState)([]);
	const [note, setNote] = (0, import_react.useState)("");
	const [busy, setBusy] = (0, import_react.useState)(false);
	async function check(raw) {
		const targets = targetsFrom(raw);
		const foundPhones = analyzePhones(raw, official.map((row) => row.e164));
		const notable = foundPhones.filter((phone) => phone.verdict !== "clean");
		const shown = notable.length ? notable : targets.length === 0 && raw.trim().length < 24 ? foundPhones : [];
		if (!targets.length && !shown.length) {
			setRows([]);
			setPhones([]);
			setNote(t.phishEmptyClip);
			return;
		}
		setBusy(true);
		setNote("");
		const found = [];
		for (const target of targets.slice(0, 12)) {
			const verdict = await scanLink(target);
			if (verdict) found.push(verdict);
		}
		setRows(found);
		setPhones(shown);
		setBusy(false);
	}
	(0, import_react.useEffect)(() => {
		if (!ready || !text) return;
		setDraft(text);
		check(text);
	}, [ready, text]);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.phishTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm leading-relaxed text-muted",
			children: t.phishLead
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("form", {
			onSubmit: (event) => {
				event.preventDefault();
				if (!ready || busy) return;
				check(draft);
			},
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("textarea", {
				value: draft,
				onChange: (event) => setDraft(event.target.value),
				rows: 4,
				className: "w-full rounded-xl border border-line bg-ink-2 p-3 text-sm",
				placeholder: t.paste
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "submit",
				disabled: !ready || busy || !draft.trim(),
				className: "mt-2 h-10 w-full rounded-xl bg-teal text-sm font-semibold text-teal-ink disabled:opacity-50",
				children: busy ? t.working : t.scanLink
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
			type: "button",
			disabled: !ready || busy,
			className: "mt-2 h-10 w-full rounded-xl border border-line text-sm disabled:opacity-50",
			onClick: () => {
				readClipboard().then((copied) => {
					if (!copied.trim()) {
						setNote(t.phishEmptyClip);
						return;
					}
					setDraft(copied);
					check(copied);
				});
			},
			children: t.phishClip
		}),
		note ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-muted",
			children: note
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("ul", {
			className: "mt-3 space-y-2",
			children: [phones.map((phone) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass p-3 text-sm",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: phone.verdict === "clean" ? "font-semibold text-teal" : "font-semibold text-gold",
						children: phone.verdict === "suspicious" ? t.suspicious : t.noIndicators
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: phone.e164 })
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
						className: "mt-1 space-y-1 text-muted",
						children: phone.reasons.map((reason) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: reasonLines(t, reason, phone.e164)[0]?.text }, reason))
					})
				]
			}, phone.e164)), rows.map((row) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass p-3 text-sm",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: row.verdict === "clean" ? "font-semibold text-teal" : "font-semibold text-gold",
						children: row.verdict === "malicious" ? t.malicious : row.verdict === "suspicious" ? t.suspicious : t.noIndicators
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1",
						children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: row.normalized })
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
						className: "mt-1 space-y-1 text-muted",
						children: row.reasons.map((reason) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: reasonLines(t, reason, reason === "lookalike" ? row.hint || row.host : row.host)[0]?.text }, reason))
					})
				]
			}, row.normalized))]
		})
	] });
}
//#endregion
export { Phish as component };
