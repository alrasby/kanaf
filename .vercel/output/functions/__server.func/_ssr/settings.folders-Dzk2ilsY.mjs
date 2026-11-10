import { S as require_jsx_runtime } from "../_libs/@tanstack/react-router+[...].mjs";
import { B as watchFolder, O as removeFolder, V as useKanaf, Z as useI18n, c as Frame, d as TopBar, o as Bidi } from "./router-CrxcCbvj.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/settings.folders-Dzk2ilsY.js
var import_jsx_runtime = require_jsx_runtime();
function Folders() {
	const { t } = useI18n();
	const folders = useKanaf((s) => s.folders);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(Frame, { children: [
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)(TopBar, { title: t.foldersTitle }),
		folders.length === 0 ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
			className: "text-sm text-muted",
			children: t.foldersEmpty
		}) : null,
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("ul", {
			className: "space-y-2",
			children: folders.map((folder) => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("li", {
				className: "glass flex items-center justify-between px-4 py-3",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Bidi, { children: folder.name }), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
					type: "button",
					className: "min-h-12 text-sm text-gold",
					onClick: () => void removeFolder(folder.id),
					children: t.removeFolder
				})]
			}, folder.id))
		}),
		/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
			type: "button",
			className: "mt-4 min-h-12 w-full rounded-2xl bg-teal font-semibold text-teal-ink",
			onClick: () => void watchFolder(),
			children: t.addFolder
		})
	] });
}
//#endregion
export { Folders as component };
