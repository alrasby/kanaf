import { S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { V as useKanaf, Z as useI18n, c as Frame, d as TopBar } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/privacy-DWl5H_an.js
var import_jsx_runtime = require_jsx_runtime();
function Privacy() {
	const { t } = useI18n();
	const shell = useKanaf((s) => s.shell);
	const paragraphs = [
		t.privacy1,
		t.privacy2,
		shell === "android" ? t.privacyApp : t.privacy3,
		t.privacy4
	];
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.privacyTitle }),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
			className: "space-y-3 text-sm leading-relaxed",
			children: paragraphs.map((paragraph) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "glass px-4 py-3",
				children: paragraph
			}, paragraph))
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
			className: "mb-2 mt-5 text-sm font-semibold",
			children: t.limitsTitle
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "space-y-3",
			children: (shell === "android" ? [
				t.limitApp1,
				t.limitApp2,
				t.limit3,
				t.limit4,
				t.limitApp5,
				t.limit6,
				t.limit7
			] : [
				t.limit1,
				t.limit2,
				t.limit3,
				t.limit4,
				t.limit5,
				t.limit6,
				t.limit7
			]).map((item) => /* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", {
				className: "glass px-4 py-3 text-sm leading-relaxed",
				children: item
			}, item))
		})
	] });
}
//#endregion
export { Privacy as component };
