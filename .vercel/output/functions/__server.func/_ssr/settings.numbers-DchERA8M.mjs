import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { G as normalizePhone, N as saveSettings, V as useKanaf, Z as useI18n, c as Frame, d as TopBar, o as Bidi } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/settings.numbers-DchERA8M.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function Numbers() {
	const { t } = useI18n();
	const settings = useKanaf((s) => s.settings);
	const shell = useKanaf((s) => s.shell);
	const [label, setLabel] = (0, import_react.useState)("");
	const [number, setNumber] = (0, import_react.useState)("");
	const [role, setRole] = (0, import_react.useState)("");
	const [bad, setBad] = (0, import_react.useState)(false);
	const [fileNote, setFileNote] = (0, import_react.useState)("");
	function mergeBook(text) {
		try {
			const parsed = JSON.parse(text);
			if (parsed.kanaf !== "numbers" || !Array.isArray(parsed.official)) {
				setFileNote(t.numbersBad);
				return;
			}
			const official = [...settings.officialNumbers];
			for (const row of parsed.official) {
				const e164 = normalizePhone(row.e164 || "");
				if (!e164) continue;
				const next = {
					id: e164,
					label: String(row.label || e164).slice(0, 80),
					e164
				};
				const at = official.findIndex((item) => item.e164 === e164);
				if (at >= 0) official[at] = next;
				else official.unshift(next);
			}
			const blocked = [...settings.blockedNumbers];
			for (const raw of parsed.blocked || []) {
				const e164 = normalizePhone(raw);
				if (e164 && !blocked.includes(e164)) blocked.unshift(e164);
			}
			saveSettings({
				...settings,
				officialNumbers: official,
				blockedNumbers: blocked
			});
			setFileNote(t.numbersImported);
		} catch {
			setFileNote(t.numbersBad);
		}
	}
	function parsed() {
		const e164 = normalizePhone(number);
		if (!e164) {
			setBad(true);
			return null;
		}
		setBad(false);
		return e164;
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.numbersTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm leading-relaxed text-muted",
			children: t.numbersLead
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
			value: label,
			onChange: (event) => setLabel(event.target.value),
			placeholder: t.numberLabel,
			className: "mb-2 h-10 w-full rounded-xl border border-line bg-ink-2 px-3 text-sm"
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
			value: number,
			onChange: (event) => setNumber(event.target.value),
			inputMode: "tel",
			placeholder: "+968",
			className: "h-10 w-full rounded-xl border border-line bg-ink-2 px-3 text-sm"
		}),
		bad ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-gold",
			children: t.numberBad
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "mt-2 grid grid-cols-2 gap-2",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "h-10 rounded-xl bg-teal text-sm font-semibold text-teal-ink",
				onClick: () => {
					const e164 = parsed();
					if (!e164) return;
					const row = {
						id: e164,
						label: label.trim() || e164,
						e164
					};
					saveSettings({
						...settings,
						officialNumbers: [row, ...settings.officialNumbers.filter((item) => item.e164 !== e164)]
					});
					setNumber("");
					setLabel("");
				},
				children: t.numberAdd
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "h-10 rounded-xl border border-line text-sm font-medium",
				onClick: () => {
					const e164 = parsed();
					if (!e164) return;
					saveSettings({
						...settings,
						blockedNumbers: [e164, ...settings.blockedNumbers.filter((item) => item !== e164)]
					});
					setNumber("");
				},
				children: t.blockAdd
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "mt-2 grid grid-cols-2 gap-2",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "h-10 rounded-xl border border-line text-sm font-medium",
				onClick: () => {
					const body = JSON.stringify({
						kanaf: "numbers",
						official: settings.officialNumbers,
						blocked: settings.blockedNumbers
					});
					const native = window.KanafNative;
					if (native?.saveText) {
						setFileNote(native.saveText("kanaf-numbers.json", body) === "ok" ? t.exported : t.failed);
						return;
					}
					const blob = new Blob([body], { type: "application/json" });
					const url = URL.createObjectURL(blob);
					const link = document.createElement("a");
					link.href = url;
					link.download = "kanaf-numbers.json";
					link.click();
					URL.revokeObjectURL(url);
					setFileNote(t.exported);
				},
				children: t.numbersExport
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "h-10 rounded-xl border border-line text-sm font-medium",
				onClick: () => {
					const native = window.KanafNative;
					if (!native?.pickNumbers || shell !== "android") {
						const input = document.createElement("input");
						input.type = "file";
						input.accept = "application/json,text/plain";
						input.onchange = () => {
							const file = input.files?.[0];
							if (!file) return;
							file.text().then(mergeBook);
						};
						input.click();
						return;
					}
					window.__kanafNumbers = (text) => {
						if (!text) return;
						mergeBook(text);
					};
					native.pickNumbers();
				},
				children: t.numbersImport
			})]
		}),
		fileNote ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-teal",
			children: fileNote
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("ul", {
			className: "mt-3 space-y-2",
			children: [settings.officialNumbers.map((row) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass flex items-center gap-2 p-3 text-sm",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
					className: "min-w-0 flex-1",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
						className: "block font-medium",
						children: row.label
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: row.e164 })]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "text-gold",
					onClick: () => void saveSettings({
						...settings,
						officialNumbers: settings.officialNumbers.filter((item) => item.id !== row.id)
					}),
					children: t.numberRemove
				})]
			}, row.id)), settings.blockedNumbers.map((e164) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass flex items-center gap-2 p-3 text-sm",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
					className: "min-w-0 flex-1 text-gold",
					children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: e164 })
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "text-gold",
					onClick: () => void saveSettings({
						...settings,
						blockedNumbers: settings.blockedNumbers.filter((item) => item !== e164)
					}),
					children: t.numberRemove
				})]
			}, e164))]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "mt-4",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					className: "text-sm font-semibold",
					children: t.callTitle
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-1 text-sm leading-relaxed text-muted",
					children: t.callLead
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "mt-2 h-10 w-full rounded-xl border border-line text-sm font-medium",
					onClick: () => {
						const native = window.KanafNative;
						if (!native?.callRole || shell !== "android") {
							setRole(t.cleanWeb);
							return;
						}
						const state = native.callRole();
						if (state === "old") setRole(t.callOld);
						else if (state === "held") setRole(t.callOn);
						else if (state === "missing") setRole(t.callOff);
						else native.askCallRole?.();
					},
					children: t.callAsk
				}),
				role ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm text-teal",
					children: role
				}) : null
			]
		})
	] });
}
//#endregion
export { Numbers as component };
