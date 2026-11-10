import { r as __exportAll$1 } from "../_runtime.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/idb-CP9J3lcI.js
var idb_CP9J3lcI_exports = /* @__PURE__ */ __exportAll$1({
	a: () => __exportAll,
	i: () => idb_exports,
	n: () => idbDelete,
	r: () => idbPut,
	t: () => idbAll
});
var __defProp = Object.defineProperty;
var __exportAll = (all, no_symbols) => {
	let target = {};
	for (var name in all) __defProp(target, name, {
		get: all[name],
		enumerable: true
	});
	if (!no_symbols) __defProp(target, Symbol.toStringTag, { value: "Module" });
	return target;
};
var idb_exports = /* @__PURE__ */ __exportAll({
	idbAll: () => idbAll,
	idbDelete: () => idbDelete,
	idbPut: () => idbPut
});
var DB_NAME = "kanaf";
var DB_VERSION = 1;
function open() {
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(DB_NAME, DB_VERSION);
		req.onupgradeneeded = () => {
			const db = req.result;
			for (const name of [
				"findings",
				"quarantine",
				"allow",
				"log",
				"meta",
				"folders"
			]) if (!db.objectStoreNames.contains(name)) db.createObjectStore(name, { keyPath: "id" });
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
}
async function idbAll(store) {
	const db = await open();
	return new Promise((resolve, reject) => {
		const req = db.transaction(store, "readonly").objectStore(store).getAll();
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
}
async function idbPut(store, value) {
	const db = await open();
	return new Promise((resolve, reject) => {
		const tx = db.transaction(store, "readwrite");
		tx.objectStore(store).put(value);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
}
async function idbDelete(store, id) {
	const db = await open();
	return new Promise((resolve, reject) => {
		const tx = db.transaction(store, "readwrite");
		tx.objectStore(store).delete(id);
		tx.oncomplete = () => resolve();
		tx.onerror = () => reject(tx.error);
	});
}
//#endregion
export { idb_CP9J3lcI_exports as a, idbPut as i, idbAll as n, idbDelete as r, __exportAll as t };
