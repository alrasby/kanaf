import { o as __toESM } from "../_runtime.mjs";
import { J as require_react, S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { V as useKanaf, Z as useI18n, c as Frame, d as TopBar } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/settings.device-CgDcTtJE.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
function amount(bytes) {
	if (typeof bytes !== "number" || bytes <= 0) return "—";
	if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
	return `${Math.round(bytes / 1e6)} MB`;
}
function Device() {
	const { t } = useI18n();
	const shell = useKanaf((s) => s.shell);
	const [info, setInfo] = (0, import_react.useState)(null);
	const asked = (0, import_react.useRef)(false);
	(0, import_react.useEffect)(() => {
		const read = () => {
			const native = window.KanafNative;
			if (!native?.deviceInfo) return;
			try {
				const parsed = JSON.parse(native.deviceInfo());
				setInfo(parsed);
				if (parsed.phone === "need" && !asked.current) {
					asked.current = true;
					native.askPhoneState?.();
				}
			} catch {
				setInfo(null);
			}
		};
		window.__kanafDevice = read;
		read();
		return () => {
			delete window.__kanafDevice;
		};
	}, []);
	const fullMah = info && info.level && info.level > 0 && info.level <= 100 && info.chargeUah && info.chargeUah > 0 ? Math.round(info.chargeUah / 1e3 / (info.level / 100)) : 0;
	const cpu = [
		info?.cpu && info.cpu !== "unknown" ? info.cpu : info?.board && info.board !== "unknown" ? info.board : "",
		info?.cores ? `${info.cores} cores` : "",
		info?.abis || ""
	].filter(Boolean).join(" · ") || "—";
	const rows = info ? [
		["Device", `${info.maker ?? ""} ${info.model ?? ""}`.trim()],
		["Android", `${info.release ?? "—"} (API ${info.sdk ?? "—"})`],
		["Security", info.patch || "—"],
		["CPU", cpu],
		["RAM", `${amount(info.ramFree)} free / ${amount(info.ramTotal)}`],
		["Storage", `${amount(info.storeFree)} free / ${amount(info.storeTotal)}`],
		["Battery", `${info.level ?? "—"}%${info.charging ? " charging" : ""}${info.tech ? ` · ${info.tech}` : ""}${fullMah ? ` · ~${fullMah} mAh` : ""}`],
		["Temp", typeof info.temp === "number" && info.temp >= 0 ? `${(info.temp / 10).toFixed(1)} °C` : "—"],
		["Voltage", typeof info.voltage === "number" && info.voltage > 0 ? `${info.voltage} mV` : "—"],
		["Screen", info.width ? `${info.width}×${info.height} · ${info.dpi} dpi` : "—"],
		["System build", info.built || "—"],
		["Factory", info.factory || "Not exposed by Android"],
		["Network", `${info.net?.link || "—"}${info.net?.vpn ? " · VPN" : ""}`]
	] : [];
	const simRows = (info?.sims ?? []).map((sim) => {
		const bits = [
			sim.operator || "—",
			sim.radio,
			sim.data ? "data" : "",
			sim.roaming ? "roaming" : ""
		].filter(Boolean);
		return [`${sim.kind} ${sim.slot}`, bits.join(" · ")];
	});
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.deviceTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "mb-3 text-sm leading-relaxed text-muted",
			children: t.devicePageLead
		}),
		shell !== "android" ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "text-sm text-muted",
			children: t.cleanWeb
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("ul", {
			dir: "ltr",
			className: "space-y-2 text-left",
			children: [
				rows.map(([label, value]) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
					className: "glass p-3 text-sm",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-xs text-muted",
						children: label
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1 font-medium break-normal text-cyan [word-break:normal]",
						children: value
					})]
				}, label)),
				simRows.map(([label, value]) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
					className: "glass p-3 text-sm",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-xs text-muted",
						children: label
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1 font-medium break-normal text-cyan [word-break:normal]",
						children: value
					})]
				}, label)),
				info?.phone === "ok" && simRows.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
					className: "glass p-3 text-sm",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-xs text-muted",
						children: "SIM"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1 font-medium text-cyan",
						children: "No active SIM or eSIM"
					})]
				}) : null
			]
		}),
		info?.sensors?.length ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			dir: "ltr",
			className: "mt-3 space-y-1 text-left text-sm text-cyan",
			children: info.sensors.map((sensor) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "break-normal [word-break:normal]",
				children: [sensor.type, sensor.name ? ` · ${sensor.name}` : ""]
			}, sensor.type))
		}) : null
	] });
}
//#endregion
export { Device as component };
