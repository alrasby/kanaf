import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { I as scanInbox, N as saveSettings, V as useKanaf, Z as useI18n, c as Frame, d as TopBar, i as Route$17, o as Bidi, p as askCloud, v as inspectMessage, y as keepMessageFinding } from "./router-CrxcCbvj.mjs";
import { t as reasonLines } from "./reasons-CVaRkdUl.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/messages-Dad85VIo.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function Messages() {
	const { t } = useI18n();
	const { auto } = Route$17.useSearch();
	const ready = useKanaf((s) => s.dbStatus === "ready");
	const shell = useKanaf((s) => s.shell);
	const settings = useKanaf((s) => s.settings);
	const [cloudNote, setCloudNote] = (0, import_react.useState)("");
	const [reading, setReading] = (0, import_react.useState)(false);
	const [sender, setSender] = (0, import_react.useState)("");
	const [text, setText] = (0, import_react.useState)("");
	const [verdict, setVerdict] = (0, import_react.useState)("");
	const [lines, setLines] = (0, import_react.useState)([]);
	const [running, setRunning] = (0, import_react.useState)(false);
	const [progress, setProgress] = (0, import_react.useState)("");
	const [status, setStatus] = (0, import_react.useState)("");
	const [hits, setHits] = (0, import_react.useState)([]);
	async function runInbox() {
		if (!ready || running) return;
		setRunning(true);
		setStatus("");
		setHits([]);
		const result = await scanInbox((done, total) => setProgress(`${done}/${total}`));
		setRunning(false);
		setProgress("");
		setStatus(result.status);
		setHits(result.hits);
	}
	(0, import_react.useEffect)(() => {
		if (!auto || !ready || shell !== "android") return;
		runInbox();
	}, [
		auto,
		ready,
		shell
	]);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.messagesTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm leading-relaxed text-muted",
			children: t.inboxHint
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
			type: "button",
			disabled: !ready || running || shell !== "android",
			className: "h-10 w-full rounded-xl bg-teal text-sm font-semibold text-teal-ink disabled:opacity-50",
			onClick: () => void runInbox(),
			children: running ? `${t.inboxProgress} ${progress}` : t.scanInbox
		}),
		shell !== "android" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-muted",
			children: t.inboxWeb
		}) : null,
		status === "denied" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-gold",
			children: t.inboxDenied
		}) : null,
		status === "ok" && hits.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-teal",
			children: t.inboxEmpty
		}) : null,
		status === "empty" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-muted",
			children: t.inboxEmpty
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "mt-3 space-y-2",
			children: hits.map((hit, index) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass p-3 text-sm",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "font-semibold",
						children: hit.verdict === "malicious" ? t.malicious : t.suspicious
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "mt-1 text-muted",
						children: [
							t.sender,
							" ",
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: hit.from || "—" })
						]
					}),
					hit.file ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "text-muted",
						children: [
							t.homeFile,
							" ",
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: hit.file })
						]
					}) : null,
					hit.detail ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: hit.detail }) }) : null,
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
						className: "mt-1 space-y-1",
						children: hit.reasons.flatMap((reason) => reasonLines(t, reason, hit.detail).map((line) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: line.text }, line.text)))
					}),
					hit.excerpt ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-2 text-muted",
						children: hit.excerpt
					}) : null
				]
			}, `${hit.from}-${hit.detail}-${index}`))
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 mt-6 text-sm text-muted",
			children: t.notStored
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", {
			className: "mb-2 block text-sm",
			children: [t.sender, /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
				value: sender,
				onChange: (e) => setSender(e.target.value),
				className: "mt-1 h-10 w-full rounded-xl border border-line bg-ink-2 px-3 text-sm"
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", {
			className: "mb-3 block text-sm",
			children: [t.message, /* @__PURE__ */ (0, import_jsx_runtime.jsx)("textarea", {
				value: text,
				onChange: (e) => setText(e.target.value),
				rows: 4,
				className: "mt-1 w-full rounded-xl border border-line bg-ink-2 p-3 text-sm"
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
			type: "button",
			disabled: !ready || !text.trim(),
			className: "h-10 w-full rounded-xl border border-line text-sm font-semibold disabled:opacity-50",
			onClick: () => {
				const result = inspectMessage(sender, text);
				const label = result.verdict === "malicious" ? t.malicious : result.verdict === "suspicious" ? t.suspicious : t.noIndicators;
				setVerdict(label);
				const reasons = result.reasons.flatMap((reason) => reasonLines(t, reason, reason === "lure-model" ? result.clause : reason === "lookalike" ? result.urls.find((url) => url.hint)?.hint || "" : result.urls[0]?.host ?? "").map((line) => line.text));
				setLines(reasons);
				setText("");
				if (result.verdict !== "clean") keepMessageFinding(sender, result.fingerprint, result.reasons[0] ?? "heuristic", result.urls[0]?.host ?? "", result.verdict);
			},
			children: t.analyze
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-2 mt-4 text-sm text-muted",
			children: t.readLead
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("label", {
			className: "flex h-10 items-center justify-center rounded-xl border border-line text-sm font-medium",
			children: [reading ? t.working : t.readImage, /* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
				type: "file",
				accept: "image/*",
				className: "hidden",
				onChange: (event) => {
					const file = event.target.files?.[0];
					event.target.value = "";
					if (!file) return;
					setReading(true);
					setCloudNote("");
					import("../_libs/tesseract.js.mjs").then((n) => /* @__PURE__ */ __toESM(n.t())).then(({ createWorker }) => createWorker("ara+eng")).then(async (worker) => {
						try {
							const sample = (await worker.recognize(file)).data.text.replace(/\s+/g, " ").trim();
							if (!sample) {
								setCloudNote(t.readEmpty);
								return;
							}
							setText(sample);
							setCloudNote("");
						} finally {
							await worker.terminate();
						}
					}).catch(() => setCloudNote(t.readFail)).finally(() => setReading(false));
				}
			})]
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-2 mt-4 text-sm text-muted",
			children: t.cloudLead
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("input", {
			type: "password",
			value: settings.cloudKey,
			autoComplete: "off",
			placeholder: t.cloudKey,
			onChange: (event) => void saveSettings({
				...settings,
				cloudKey: event.target.value
			}),
			className: "mb-2 h-10 w-full rounded-xl border border-line bg-ink-2 px-3 text-sm"
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
			type: "button",
			disabled: !text.trim(),
			className: "h-10 w-full rounded-xl border border-line text-sm font-semibold disabled:opacity-50",
			onClick: () => {
				setCloudNote("");
				askCloud(text, settings.cloudKey).then((result) => {
					if (result === "need") {
						setCloudNote(t.cloudNeed);
						return;
					}
					if (result === "fail") {
						setCloudNote(t.failed);
						return;
					}
					if (result.verdict === "clean") {
						setCloudNote(t.cloudClean);
						return;
					}
					setVerdict(t.suspicious);
					setLines(reasonLines(t, "cloud-lure", result.clause).map((line) => line.text));
					const local = inspectMessage(sender, text);
					keepMessageFinding(sender, local.fingerprint, "cloud-lure", result.clause, "suspicious");
				});
			},
			children: t.cloudSend
		}),
		cloudNote ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-2 text-sm text-gold",
			children: cloudNote
		}) : null,
		verdict ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
			className: "glass mt-4 p-4 text-sm",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "font-semibold",
					children: verdict
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
					className: "mt-2 text-muted",
					children: [
						t.fingerprint,
						" ",
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: sender || "—" })
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
					className: "mt-2 space-y-1",
					children: lines.map((line) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: line }, line))
				})
			]
		}) : null
	] });
}
//#endregion
export { Messages as component };
