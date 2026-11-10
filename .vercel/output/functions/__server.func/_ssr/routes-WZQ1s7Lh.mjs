import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime, b as useNavigate, y as Link } from "../_libs/@tanstack/react-router+[...].mjs";
import { E as refreshSources, F as scanDevice, R as setRealtime, V as useKanaf, X as scanSummary, Y as resultsLabel, Z as useI18n, b as metered, c as Frame, g as chooseFolder, h as chooseFiles, l as HomeBar, m as cancelScan, u as Notice } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/routes-WZQ1s7Lh.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function Home() {
	const { t, locale } = useI18n();
	const navigate = useNavigate();
	const dbStatus = useKanaf((s) => s.dbStatus);
	const progress = useKanaf((s) => s.dbProgress);
	const findings = useKanaf((s) => s.findings.length);
	const scan = useKanaf((s) => s.scan);
	const lastScan = useKanaf((s) => s.lastScan);
	const shell = useKanaf((s) => s.shell);
	const realtime = useKanaf((s) => s.realtime);
	const note = useKanaf((s) => s.realtimeNote);
	const wifiOnly = useKanaf((s) => s.settings.wifiOnly);
	const integrity = useKanaf((s) => s.integrity);
	const [link, setLink] = (0, import_react.useState)("");
	const [askData, setAskData] = (0, import_react.useState)(false);
	const ready = dbStatus === "ready" && !scan.running;
	const valid = link.trim().length > 0;
	async function goLink() {
		if (!valid || !ready) return;
		await navigate({
			to: "/phish",
			search: { text: link.trim() }
		});
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(HomeBar, {}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Notice, {}),
		dbStatus === "loading" ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
			className: "mb-3 text-center text-sm text-muted",
			role: "status",
			children: [
				t.preparing,
				" ",
				progress,
				"%"
			]
		}) : null,
		dbStatus === "error" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-center text-sm text-gold",
			children: t.failedDb
		}) : null,
		!scan.running && lastScan && findings === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-center text-sm text-teal",
			children: scanSummary(locale, lastScan.files)
		}) : null,
		shell === "android" && !scan.running && !lastScan ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-center text-xs leading-relaxed text-muted",
			children: t.deviceHint
		}) : null,
		integrity === "repacked" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-center text-sm text-gold",
			children: t.integrityBad
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
			className: "overflow-hidden rounded-3xl border border-line bg-ink-2",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
				className: "bg-[radial-gradient(circle_at_50%_0%,rgba(32,201,151,0.16),transparent_62%)] px-4 py-4",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center gap-3",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						disabled: !ready,
						onClick: () => void (shell === "android" ? scanDevice("deep") : chooseFolder("deep")),
						className: "grid h-14 w-14 shrink-0 place-items-center rounded-full border border-gold/50 bg-ink text-sm font-semibold text-cyan disabled:opacity-50",
						"aria-label": t.scanDeep,
						children: "K"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
						className: "min-w-0 flex-1",
						children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "text-base font-semibold leading-tight",
							children: scan.running && scan.mode === "deep" ? `${t.scanning} ${scan.total ? Math.round(scan.done / scan.total * 100) : 0}%` : t.scanDeep
						}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "mt-1 text-xs leading-snug text-muted",
							children: ready ? t.tagline : t.notReady
						})]
					})]
				})
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: `grid border-t border-line ${shell === "android" && !scan.running ? "grid-cols-2" : "grid-cols-1"}`,
				children: [scan.running ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					onClick: cancelScan,
					className: "h-11 text-sm font-medium",
					children: t.cancel
				}) : /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					disabled: !ready,
					onClick: () => void (shell === "android" ? scanDevice("quick") : chooseFolder("quick")),
					className: "h-11 text-sm font-medium disabled:opacity-50",
					children: t.scanQuick
				}), shell === "android" && !scan.running ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					disabled: !ready,
					onClick: () => void chooseFolder("deep"),
					className: "h-11 border-s border-line text-sm font-medium disabled:opacity-50",
					children: t.scanFolder
				}) : null]
			})]
		}),
		scan.running ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 truncate text-center text-xs text-muted",
			children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)("bdi", { children: scan.phase === "enum" ? t.listing : scan.current })
		}) : null,
		findings > 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
			to: "/results",
			className: "mt-3 flex h-11 items-center justify-center rounded-xl bg-gold/15 text-sm font-semibold text-gold",
			children: resultsLabel(locale, findings)
		}) : null,
		lastScan && lastScan.downloads === false && !scan.running ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-center text-xs text-muted",
			children: t.downloadsClosed
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("form", {
			className: "mt-3",
			onSubmit: (event) => {
				event.preventDefault();
				goLink();
			},
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("label", {
				className: "mb-2 block text-xs font-semibold text-muted",
				htmlFor: "kanaf-check",
				children: t.phishTitle
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "flex gap-2",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
					id: "kanaf-check",
					value: link,
					onChange: (event) => setLink(event.target.value),
					placeholder: t.paste,
					className: "h-11 min-w-0 flex-1 rounded-xl border border-line bg-ink-2 px-3 text-sm text-fg outline-none",
					"aria-label": t.paste
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "submit",
					disabled: !ready || !valid,
					className: "h-11 shrink-0 rounded-xl bg-gold px-4 text-sm font-semibold text-ink disabled:opacity-50",
					children: t.scanLink
				})]
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
			to: "/qr",
			className: "mt-2 flex h-11 items-center justify-center rounded-xl border border-line bg-ink-2 text-sm font-medium",
			children: t.qrTitle
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "mt-3 grid grid-cols-2 gap-2",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					onClick: () => void navigate({
						to: "/messages",
						search: { auto: shell === "android" }
					}),
					className: "flex h-11 items-center justify-center rounded-xl border border-line bg-ink-2 px-2 text-center text-sm font-medium",
					children: t.homeMsg
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					disabled: !ready,
					onClick: () => {
						chooseFiles().then((result) => {
							if (result === "clean" || result === "hit") navigate({ to: "/checked" });
						});
					},
					className: "flex h-11 items-center justify-center rounded-xl border border-line bg-ink-2 px-2 text-center text-sm font-medium disabled:opacity-50",
					children: t.homeFile
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
					to: "/behavior",
					className: "flex h-11 items-center justify-center rounded-xl border border-line bg-ink-2 px-2 text-center text-sm font-medium",
					children: t.engineBehavior
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
					to: "/advisor",
					className: "flex h-11 items-center justify-center rounded-xl border border-line bg-ink-2 px-2 text-center text-sm font-medium",
					children: t.homeAdvisor
				})
			]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "mt-2 grid grid-cols-2 gap-2",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				disabled: dbStatus !== "ready" || progress < 100,
				onClick: () => {
					if (wifiOnly && metered() === true) {
						setAskData(true);
						return;
					}
					refreshSources(false);
				},
				className: "flex h-10 items-center justify-center rounded-xl border border-line bg-ink-2 text-sm font-medium disabled:opacity-50",
				children: dbStatus === "ready" && progress < 100 ? `${t.updating} ${progress}%` : t.homeUpdate
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
				to: "/settings/device",
				className: "flex h-10 items-center justify-center rounded-xl border border-line bg-ink-2 text-sm font-medium",
				children: t.deviceTitle
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "mt-1 flex items-stretch gap-2",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
				to: "/settings",
				className: "flex h-11 shrink-0 items-center justify-center rounded-xl border border-line bg-ink-2 px-3 text-sm font-medium",
				children: t.settings
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				role: "switch",
				"aria-checked": realtime,
				"aria-label": t.ariaSwitch,
				onClick: () => void setRealtime(!realtime),
				className: `flex h-11 min-w-0 flex-1 items-center justify-center rounded-xl border px-3 text-sm font-medium ${realtime ? "border-teal bg-ink-2 text-teal" : "border-line bg-ink-2"}`,
				children: t.realtime
			})]
		}),
		note === "need" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-3 text-sm text-gold",
			children: t.realtimeNeed
		}) : null,
		note === "missing" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-3 text-sm text-muted",
			children: t.realtimeMissing
		}) : null,
		note === "fail" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-3 text-sm text-gold",
			children: t.realtimeFail
		}) : null,
		note === "watching" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-3 text-sm text-teal",
			children: shell === "android" ? t.liveAndroid : t.liveWatching
		}) : null,
		askData ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "glass mt-3 p-4 text-sm",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: t.cellularWarn }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "mt-3 min-h-12 w-full rounded-2xl bg-gold font-semibold text-ink",
				onClick: () => {
					setAskData(false);
					refreshSources(true);
				},
				children: t.downloadAnyway
			})]
		}) : null
	] });
}
//#endregion
export { Home as component };
