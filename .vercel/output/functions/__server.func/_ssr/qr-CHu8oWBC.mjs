import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime, b as useNavigate } from "../_libs/@tanstack/react-router+[...].mjs";
import { V as useKanaf, Z as useI18n, c as Frame, d as TopBar } from "./router-CrxcCbvj.mjs";
import { t as require_jsQR } from "../_libs/jsqr.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/qr-CHu8oWBC.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var import_jsQR = /* @__PURE__ */ __toESM(require_jsQR());
function Qr() {
	const { t } = useI18n();
	const navigate = useNavigate();
	const shell = useKanaf((s) => s.shell);
	const videoRef = (0, import_react.useRef)(null);
	const [live, setLive] = (0, import_react.useState)(false);
	const [note, setNote] = (0, import_react.useState)("");
	const [text, setText] = (0, import_react.useState)("");
	const stopRef = (0, import_react.useRef)(null);
	(0, import_react.useEffect)(() => () => stopRef.current?.(), []);
	function stop() {
		stopRef.current?.();
		stopRef.current = null;
		setLive(false);
	}
	async function start() {
		stop();
		setText("");
		setNote("");
		if (shell === "android") {
			if (!await new Promise((resolve) => {
				let settled = false;
				const finish = (ok) => {
					if (settled) return;
					settled = true;
					resolve(ok);
				};
				window.__kanafCamera = finish;
				window.KanafNative?.askCamera?.();
				window.setTimeout(() => finish(false), 2e4);
			})) {
				setNote(t.cleanWeb);
				return;
			}
		}
		const stream = await navigator.mediaDevices.getUserMedia({
			video: { facingMode: "environment" },
			audio: false
		});
		const video = videoRef.current;
		if (!video) {
			stream.getTracks().forEach((track) => track.stop());
			return;
		}
		video.srcObject = stream;
		video.muted = true;
		await video.play();
		setLive(true);
		let timer = 0;
		const canvas = document.createElement("canvas");
		const Detector = window.BarcodeDetector;
		const detector = Detector ? new Detector({ formats: ["qr_code"] }) : null;
		const tick = async () => {
			if (!video.videoWidth) {
				timer = window.setTimeout(tick, 200);
				return;
			}
			let found = "";
			try {
				if (detector) found = (await detector.detect(video))[0]?.rawValue || "";
				else {
					canvas.width = video.videoWidth;
					canvas.height = video.videoHeight;
					const ctx = canvas.getContext("2d", { willReadFrequently: true });
					if (ctx) {
						ctx.drawImage(video, 0, 0);
						const frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
						found = (0, import_jsQR.default)(frame.data, frame.width, frame.height)?.data || "";
					}
				}
			} catch {
				found = "";
			}
			if (found) {
				setText(found);
				setNote("");
				stop();
				return;
			}
			timer = window.setTimeout(tick, 350);
		};
		stopRef.current = () => {
			window.clearTimeout(timer);
			stream.getTracks().forEach((track) => track.stop());
			video.srcObject = null;
		};
		timer = window.setTimeout(tick, 350);
	}
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.qrTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm leading-relaxed text-muted",
			children: t.qrLead
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("video", {
			ref: videoRef,
			className: "mb-3 aspect-[3/4] w-full rounded-xl bg-ink object-cover",
			playsInline: true
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
			type: "button",
			className: "h-11 w-full rounded-xl bg-teal text-sm font-semibold text-teal-ink",
			onClick: () => void (live ? stop() : start().catch(() => setNote(t.failed))),
			children: live ? t.qrStop : t.qrStart
		}),
		note ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mt-3 text-sm text-gold",
			children: note
		}) : null,
		text ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			className: "mt-3",
			children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "break-all text-sm",
				dir: "ltr",
				children: text
			}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				className: "mt-2 h-11 w-full rounded-xl bg-gold text-sm font-semibold text-ink",
				onClick: () => void navigate({
					to: "/phish",
					search: { text }
				}),
				children: t.scanLink
			})]
		}) : null
	] });
}
//#endregion
export { Qr as component };
