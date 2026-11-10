import { o as __toESM } from "../_runtime.mjs";
import { i as idbPut, n as idbAll, r as idbDelete, t as __exportAll } from "./idb-CP9J3lcI.mjs";
import { J as require_react, S as require_jsx_runtime, _ as createFileRoute, d as Scripts, f as HeadContent, g as lazyRouteComponent, h as Outlet, m as createRouter, v as createRootRoute, x as useRouter, y as Link } from "../_libs/@tanstack/react-router+[...].mjs";
import { t as TriangleAlert } from "../_libs/lucide-react.mjs";
import { a as union, i as string, n as number, r as object, t as literal } from "../_libs/zod.mjs";
import { t as create } from "../_libs/zustand.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/router-CrxcCbvj.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var FALLBACK_MESSAGE = "An unexpected error occurred. Try reloading the page.";
function errorMessage(error) {
	if (error instanceof Error && error.message) return error.message;
	if (typeof error === "string" && error) return error;
	return FALLBACK_MESSAGE;
}
function AppErrorComponent({ error }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("main", {
		className: "flex min-h-screen flex-col items-center justify-center gap-3 px-6 text-center bg-zinc-50 text-zinc-900 dark:bg-zinc-950 dark:text-zinc-50",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
				className: "text-red-500",
				"aria-hidden": "true",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(TriangleAlert, {
					className: "size-10",
					strokeWidth: 2
				})
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", {
				className: "text-lg font-semibold",
				children: "Something went wrong"
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
				className: "max-w-md text-sm break-words text-zinc-500 dark:text-zinc-400",
				children: errorMessage(error)
			})
		]
	});
}
/**
* Path-based preview hosts serve the dev server under `/{port_id}/` and strip
* that prefix before forwarding, so SSR sees `/` while the browser URL keeps the
* prefix. TanStack Start resets `basepath` on hydration, so a `rewrite` keeps
* client routing and generated links aligned with the public URL.
*/
var PATH_BASED_PREVIEW_HOSTS = /* @__PURE__ */ new Set([
	"preview.grok.genai.mil",
	"preview.grok.mil",
	"preview.grokgsac.com"
]);
var PORT_ID_PREFIX = /^\/hds-[a-z0-9]+-\d+-[a-z0-9]+(?=\/|$)/i;
function previewPathPrefix(hostname, pathname) {
	if (!PATH_BASED_PREVIEW_HOSTS.has(hostname.toLowerCase())) return void 0;
	return PORT_ID_PREFIX.exec(pathname)?.[0];
}
function prefixRewrite(prefix) {
	return {
		input: ({ url }) => {
			if (url.pathname === prefix) url.pathname = "/";
			else if (url.pathname.startsWith(`${prefix}/`)) url.pathname = url.pathname.slice(prefix.length);
			return url;
		},
		output: ({ url }) => {
			url.pathname = `${prefix}${url.pathname}`;
			return url;
		}
	};
}
function previewPathRewrite() {
	if (typeof window === "undefined") return void 0;
	const prefix = previewPathPrefix(window.location.hostname, window.location.pathname);
	return prefix ? prefixRewrite(prefix) : void 0;
}
/**
* App-wide client provider mounted once near the root (in `src/routes/__root.tsx`):
*
*   <AuthProvider><Outlet /></AuthProvider>
*
* Better Auth's React client (`@/lib/auth/client`) needs NO context provider —
* its `useSession()` works standalone — so this is a passthrough today. It's
* kept as the single, stable mount point for any future client-side providers
* (e.g. a toast or theme provider) without churning the root shell.
*/
function AuthProvider({ children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(import_jsx_runtime.Fragment, { children });
}
var CONNECTOR_TOKEN_READY_EVENT = "grok:connector-token-ready";
function isGrokEmbedderOrigin(origin) {
	try {
		const url = new URL(origin);
		if (url.protocol !== "https:" && url.protocol !== "http:") return false;
		const host = url.hostname.toLowerCase();
		if (host === "grok.com" || host.endsWith(".grok.com")) return true;
		if (host === "localhost" || host === "127.0.0.1" || host === "[::1]") return true;
		return false;
	} catch {
		return false;
	}
}
function isSandboxPreviewGuestHost(hostname) {
	const host = hostname.toLowerCase();
	return host === "grok-sandbox.com" || host.endsWith(".grok-sandbox.com");
}
function isRemintPreviewPair(guestHost, parentHost) {
	const guest = guestHost.toLowerCase();
	const parent = parentHost.toLowerCase();
	const i = guest.indexOf(".preview.");
	if (i <= 0) return false;
	const label = guest.slice(0, i);
	const rest = guest.slice(i + 9);
	if (label.includes(".") || !rest.includes(".")) return false;
	return parent === rest || parent === `grok.${rest}`;
}
function resolveParentEmbedderOrigin(parentIsSelf, referrer, ancestorOrigin, guestHostname = "") {
	if (parentIsSelf) return null;
	for (const candidate of [referrer, ancestorOrigin ?? ""].filter(Boolean)) try {
		const url = new URL(candidate.includes("://") ? candidate : `https://${candidate}`);
		if (url.protocol !== "https:" && url.protocol !== "http:") continue;
		if (isGrokEmbedderOrigin(url.origin)) return url.origin;
		if (isSandboxPreviewGuestHost(guestHostname) || isRemintPreviewPair(guestHostname, url.hostname)) return url.origin;
	} catch {}
	return null;
}
/**
* Guest side of the grok-web ↔ sandbox preview postMessage bridge.
*
* Activates only when this page is framed by an allowlisted Grok embedder.
* Top-level runs (download/export, local `npm run dev`, deployed sites) noop.
*/
var PREVIEW_BRIDGE_CHANNEL = "grok-preview-bridge";
var EnvelopeSchema = object({
	channel: literal(PREVIEW_BRIDGE_CHANNEL),
	version: number().int().positive(),
	type: string().min(1)
});
var HelloSchema = EnvelopeSchema.extend({ type: literal("hello") });
var NavigateSchema = EnvelopeSchema.extend({
	type: literal("navigate"),
	path: string().min(1)
});
var HistorySchema = EnvelopeSchema.extend({
	type: literal("history"),
	delta: union([literal(-1), literal(1)])
});
var ConnectorTokenReadySchema = EnvelopeSchema.extend({ type: literal("connector-token-ready") });
function isSafeBridgePath(path) {
	if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\")) return false;
	try {
		return new URL(path, "https://preview.invalid").origin === "https://preview.invalid";
	} catch {
		return false;
	}
}
/**
* Origin of the Grok embedder framing this page, or null when the page runs
* top-level (download/export, local `npm run dev`, deployed sites) or under a
* non-Grok parent. Client-only; null during SSR.
*/
function resolveCurrentEmbedderOrigin() {
	if (typeof window === "undefined") return null;
	const ancestorOrigin = typeof location.ancestorOrigins !== "undefined" && location.ancestorOrigins.length > 0 ? location.ancestorOrigins[0] : null;
	return resolveParentEmbedderOrigin(window.parent === window, document.referrer, ancestorOrigin, window.location.hostname);
}
/**
* Install host↔guest messaging. Returns a dispose function.
* Noops (returns a no-op dispose) when not embedded under a Grok parent.
*/
function installPreviewHostBridge(options = {}) {
	const parentOrigin = resolveCurrentEmbedderOrigin();
	if (parentOrigin === null) return () => {};
	const ROOT_STATE_KEY = "__grokPreviewBridgeRoot";
	const originalPushState = window.history.pushState.bind(window.history);
	const originalReplaceState = window.history.replaceState.bind(window.history);
	const isAtHistoryRoot = () => {
		const state = window.history.state;
		return Boolean(state && typeof state === "object" && state[ROOT_STATE_KEY] === true);
	};
	try {
		const current = window.history.state;
		if (!(current !== null && typeof current === "object" && Object.prototype.hasOwnProperty.call(current, ROOT_STATE_KEY))) {
			const isRoot = window.history.length <= 1;
			originalReplaceState(current && typeof current === "object" ? {
				...current,
				[ROOT_STATE_KEY]: isRoot
			} : { [ROOT_STATE_KEY]: isRoot }, "", window.location.href);
		}
	} catch {}
	const post = (message) => {
		window.parent.postMessage(message, parentOrigin);
	};
	const reportLocation = () => {
		post({
			channel: PREVIEW_BRIDGE_CHANNEL,
			version: 1,
			type: "location",
			path: window.location.pathname || "/",
			search: window.location.search,
			hash: window.location.hash
		});
	};
	const reportRoutes = () => {
		const paths = options.getRoutePaths?.() ?? [];
		post({
			channel: PREVIEW_BRIDGE_CHANNEL,
			version: 1,
			type: "routes",
			paths
		});
	};
	const defaultNavigate = (path) => {
		if (!isSafeBridgePath(path)) return;
		try {
			const url = new URL(path, window.location.origin);
			if (url.origin !== window.location.origin) return;
			const next = `${url.pathname}${url.search}${url.hash}`;
			window.history.pushState(window.history.state, "", next);
			window.dispatchEvent(new PopStateEvent("popstate", { state: window.history.state }));
		} catch {}
	};
	const navigate = (path) => {
		if (!isSafeBridgePath(path)) return;
		if (options.navigate) {
			options.navigate(path);
			return;
		}
		defaultNavigate(path);
	};
	const announce = () => {
		reportLocation();
		reportRoutes();
		post({
			channel: PREVIEW_BRIDGE_CHANNEL,
			version: 1,
			type: "ready"
		});
	};
	const onHello = (data) => {
		if (!HelloSchema.safeParse(data).success) return;
		announce();
	};
	const onNavigate = (data) => {
		const parsed = NavigateSchema.safeParse(data);
		if (!parsed.success) return;
		navigate(parsed.data.path);
		queueMicrotask(reportLocation);
	};
	const onHistory = (data) => {
		const parsed = HistorySchema.safeParse(data);
		if (!parsed.success) return;
		if (parsed.data.delta === -1 && isAtHistoryRoot()) return;
		window.history.go(parsed.data.delta);
	};
	const onConnectorTokenReady = (data) => {
		if (!ConnectorTokenReadySchema.safeParse(data).success) return;
		window.dispatchEvent(new Event(CONNECTOR_TOKEN_READY_EVENT));
	};
	const hostMessageHandlers = /* @__PURE__ */ new Map([
		["hello", onHello],
		["navigate", onNavigate],
		["history", onHistory],
		["connector-token-ready", onConnectorTokenReady]
	]);
	const onMessage = (event) => {
		if (event.source !== window.parent) return;
		if (event.origin !== parentOrigin) return;
		const envelope = EnvelopeSchema.safeParse(event.data);
		if (!envelope.success || envelope.data.version !== 1) return;
		hostMessageHandlers.get(envelope.data.type)?.(event.data);
	};
	const onPopState = () => {
		reportLocation();
	};
	const onHashChange = () => {
		reportLocation();
	};
	window.history.pushState = (data, unused, url) => {
		const next = data && typeof data === "object" ? {
			...data,
			[ROOT_STATE_KEY]: false
		} : data;
		originalPushState(next, unused, url);
		reportLocation();
	};
	window.history.replaceState = (data, unused, url) => {
		const next = isAtHistoryRoot() ? {
			...data && typeof data === "object" ? data : {},
			[ROOT_STATE_KEY]: true
		} : data;
		originalReplaceState(next, unused, url);
		reportLocation();
	};
	window.addEventListener("message", onMessage);
	window.addEventListener("popstate", onPopState);
	window.addEventListener("hashchange", onHashChange);
	announce();
	return () => {
		window.removeEventListener("message", onMessage);
		window.removeEventListener("popstate", onPopState);
		window.removeEventListener("hashchange", onHashChange);
		window.history.pushState = originalPushState;
		window.history.replaceState = originalReplaceState;
	};
}
/** Collect static path patterns from a TanStack route tree (best-effort). */
function collectRoutePathsFromTree(routeTree) {
	const paths = /* @__PURE__ */ new Set();
	const walk = (node) => {
		if (!node || typeof node !== "object") return;
		const record = node;
		const full = typeof record.fullPath === "string" ? record.fullPath : typeof record.path === "string" ? record.path : null;
		if (full !== null && full !== "") paths.add(full.startsWith("/") ? full : `/${full}`);
		else if (full === "") paths.add("/");
		const children = record.children;
		if (Array.isArray(children)) for (const child of children) walk(child);
		else if (children && typeof children === "object") for (const child of Object.values(children)) walk(child);
	};
	walk(routeTree);
	return [...paths];
}
/**
* Mount once in `__root.tsx` so the Grok preview chrome can drive navigation
* (and later receive registered routes). Noops when the app is not embedded.
*/
function PreviewHostBridge() {
	const router = useRouter();
	(0, import_react.useEffect)(() => {
		return installPreviewHostBridge({
			navigate: (path) => {
				router.history.push(path);
			},
			getRoutePaths: () => collectRoutePathsFromTree(router.routeTree)
		});
	}, [router]);
	return null;
}
var en = {
	name: "Kanaf",
	tagline: "Scan your device. The decision is yours.",
	engineLocal: "Local hashes",
	engineBehavior: "On-device behavior",
	engineCloud: "Cloud feeds",
	cloudHint: "A device scan refreshes signature feeds if they are older than a day. Files stay here. There is no remote sandbox.",
	integrityBad: "This copy of Kanaf was modified. Database updates are blocked.",
	behaviorRev: "Behavior model 3",
	behaviorLead: "Reads declared permissions and services. It does not watch the screen or keystrokes. A hit needs a strong pair, such as an overlay with accessibility, or SMS without a launcher. Known store apps are skipped. A hit is suspicious, not a conviction.",
	behaviorScan: "Check installed apps",
	behaviorEmpty: "No installed app matched the strong behavior rules.",
	behaviorFail: "The app list could not be read. Try again.",
	behaviorWeb: "This check runs on the phone, where app permissions can be read.",
	phishTitle: "Phishing protection",
	phishLead: "The address or number stays on this device. A local explainable score checks phishing lists, lookalike brands, hidden destinations, planted names, premium-rate numbers, and callback lures. Nothing is uploaded, and the link is not opened.",
	phishClip: "Check copied text",
	phishEmptyClip: "No link or phone number in that text.",
	phonePremium: "This is an international premium-rate number used in callback fraud. Do not call it.",
	phoneLure: "The message asks you to call a personal number while talking about a bank, a code, or an account. Official notices use short codes, not a private mobile.",
	userinfo: "The text before @ is not the real site. The destination is the host after @.",
	brandHost: "The name of a known bank or service appears in a different site.",
	macro: "The document contains a macro. A macro can run code when the file is opened.",
	docLink: "The document points at a link that is already suspicious or listed.",
	polyglot: "Data is glued after the end of the picture. Pictures do not need a program trailer.",
	pdfLaunch: "The PDF asks the reader to launch another program.",
	pdfActive: "The PDF runs a script as soon as it opens.",
	fileReport: "File check",
	fileLead: "Each file is hashed on this device. Zip and Office packages are opened. Pictures are not recognized by sight. RAR is identified and hashed, not unpacked. A clean result is a result.",
	fileClean: "No known threat in this file.",
	fileSkipped: "This file was too large or could not be read.",
	kindApk: "Android package: signature, certificate, permissions, and inner files.",
	kindZip: "Zip archive: inner files are hashed. Encrypted entries are skipped.",
	kindOffice: "Office document: macros, embedded programs, and dangerous links.",
	kindImage: "Picture: hash and a trailer after the image. No visual recognition.",
	kindPdf: "PDF: hash, plus auto-launch and startup scripts.",
	kindRar: "RAR: identified and hashed. Compressed contents are not unpacked.",
	kindOle: "Old Office file: hash, plus a search for a macro store.",
	kindOther: "This type is hashed only. It is not unpacked.",
	notices: "App notification previews",
	noticesLead: "With this system permission, Kanaf reads a preview only when it contains a link, checks that link, and does not keep the message. Hidden WhatsApp previews cannot be read.",
	noticesOpen: "Open notification access",
	noticesOn: "Notification access is on.",
	noticesOff: "Notification access is off.",
	lang: "عربي",
	scanDeep: "Deep device scan",
	scanQuick: "Quick scan",
	results: "Results",
	paste: "Link, number, or message",
	scanLink: "Check",
	messages: "Scan a message",
	homeMsg: "Messages",
	addFile: "Scan a file or document",
	homeFile: "Scan file",
	update: "Update signature databases",
	homeUpdate: "Databases",
	realtime: "Real-time protection",
	advisor: "Security advisor",
	homeAdvisor: "Advisor",
	settings: "Settings",
	back: "Back",
	resultsTitle: "Scan results",
	decide: "Decide",
	allow: "Allow it to run",
	quarantine: "Move to quarantine",
	delete: "Delete from device",
	clean: "No known threats were found.",
	preparing: "Preparing signature databases",
	notReady: "Databases are not ready yet",
	failedDb: "Could not load the databases",
	retry: "Try again",
	cancel: "Cancel",
	listing: "Listing files",
	scanning: "Scanning",
	linkTitle: "Link scan",
	noIndicators: "No indicators",
	suspicious: "Suspicious",
	malicious: "Known malicious",
	open: "Open",
	confirmOpen: "Open this address in a new tab? Kanaf will not open it for you until you confirm.",
	expand: "Expand redirects",
	expandWarn: "This step contacts the site from your browser and reveals your address. It is optional.",
	expandFail: "The browser blocked reading the destination. The address was not sent to a server.",
	messagesTitle: "Message scan",
	sender: "Sender",
	message: "Message",
	analyze: "Scan message",
	notStored: "Inbox text is not stored. Only a suspicious sender, the reason, and a fingerprint are kept.",
	scanInbox: "Scan the inbox",
	inboxHint: "Reads the SMS inbox and MMS text and attachments that Android exposes. WhatsApp and Telegram cannot be read. A message is listed only for a known-bad link, a brand lookalike, a public IP link, or a malicious attachment.",
	inboxEmpty: "No suspicious messages in the inbox.",
	inboxDenied: "SMS permission was denied. Nothing was read.",
	inboxWeb: "This browser cannot read the phone inbox. Paste one message below.",
	inboxProgress: "Scanning messages",
	trusted: "Trusted senders",
	addSender: "Add sender",
	quarantineTitle: "Quarantine",
	vault: "Quarantined",
	allowed: "Allowed",
	restore: "Restore",
	purge: "Delete permanently",
	revoke: "Revoke allow",
	emptyVault: "The vault is empty.",
	emptyAllow: "Nothing is on the allow list.",
	emptyResults: "Nothing is waiting for a decision.",
	advisorTitle: "Security advisor",
	noAdvice: "No recommendations right now.",
	settingsTitle: "Settings",
	schedule: "Scheduled scan",
	folders: "Watched folders",
	sources: "Signature sources",
	log: "Scan log",
	network: "Network options",
	limits: "Protection limits",
	privacy: "Privacy",
	wifiOnly: "Download databases on Wi-Fi only",
	cellularWarn: "The connection looks metered. Databases are large.",
	downloadAnyway: "Download on this connection",
	sourcesTitle: "Signature sources",
	license: "License",
	count: "Records",
	updated: "Updated",
	version: "Version",
	notLoaded: "Not loaded",
	downloading: "Downloading",
	ready: "Ready",
	failed: "Failed",
	logEmpty: "No scans yet.",
	foldersEmpty: "No folder is being watched.",
	addFolder: "Choose a folder",
	remove: "Remove",
	daily: "Daily",
	weekly: "Weekly",
	charging: "Only while charging",
	scheduleHelp: "The scan runs while Kanaf is open. A browser cannot keep scanning after you leave.",
	enable: "Enabled",
	notifyAsk: "Kanaf can notify you when something is waiting for your decision.",
	enableNotify: "Allow notifications",
	realtimeNeed: "Waiting for notification permission.",
	realtimeMissing: "This browser cannot watch a folder without constant polling, so real-time protection stays off.",
	liveWatching: "Watching the folder you chose.",
	confirmDelete: "Delete this file from the device?",
	confirmVault: "Move a copy into the encrypted vault?",
	confirmPurge: "Delete this item from the vault forever?",
	confirmRestore: "Restore this file? It will download to your device.",
	deleteBlocked: "The browser did not grant deletion. The file is still in place.",
	originalRemains: "The original file is still in place because deletion was not granted. The vault holds an encrypted copy.",
	moved: "The file is in the encrypted vault.",
	allowedDone: "Allowed. It will be skipped on later scans.",
	eicar: "Run the EICAR test",
	eicarHelp: "Runs the standard 68-byte test file through the real engine. It is not a virus.",
	eicarHit: "The EICAR test file was detected.",
	eicarMiss: "The test file was not detected. The databases may be incomplete.",
	permissions: "Permissions",
	noPerms: "No permissions were extracted.",
	reason: "Reason",
	hashMatch: "The file matches a known signature.",
	eicarReason: "This is the EICAR test file. The detection line is working.",
	badCert: "The signing certificate is on a known-malware list.",
	heuristic: "Static indicators look suspicious. This is not a conviction.",
	archiveDepth: "The archive is deeper than the safe limit, so inner levels were not opened.",
	zipLimit: "The archive hit a safety limit and was not fully opened.",
	zipCorrupt: "The archive could not be read completely.",
	listed: "The address is on a loaded malicious-URL list.",
	ipHost: "The host is a raw IP address.",
	shortener: "This is a link shortener, so the destination is hidden.",
	punycode: "The host uses punycode.",
	lookalike: "The host resembles",
	lureModel: "The wording model marked this sentence:",
	cloudLure: "The cloud model, which saw only this text, marked:",
	cloudSend: "Send this text to the cloud",
	cloudLead: "Only the text in the box is sent. Files and other messages stay on the phone.",
	cloudKey: "Cloud key, stored on this phone",
	cloudNeed: "No cloud key is saved, so nothing was sent.",
	cloudClean: "The cloud model did not mark this text.",
	readImage: "Read a picture",
	readLead: "Text is read from the picture on this phone, then checked. The picture is not uploaded.",
	readEmpty: "No text was read from the picture.",
	readFail: "The picture could not be read on this phone.",
	offDomain: "The sender name matches a trusted sender, but a link is outside that sender's domains.",
	overlay: "Asks for a screen overlay together with an accessibility service.",
	smsNet: "Asks to read or receive messages and to use the internet.",
	admin: "Asks for device-admin access.",
	launcher: "No launcher icon was found, while a background component was.",
	dynamic: "Loads code dynamically and looks obfuscated.",
	packer: "Contains a known packer.",
	testKey: "Signed with a test or debug key.",
	installNet: "Can request app installs and use the internet.",
	dexSms: "The code sends text messages and uses an accessibility service.",
	hideIcon: "The code can hide its own icon, together with message or accessibility use.",
	dexAdmin: "The code asks to become a device administrator.",
	smsAccess: "Asks to read messages and to use an accessibility service.",
	smsOverlay: "Asks to read messages and to draw over other screens.",
	certChanged: "The signing certificate changed after an update. The previous and current fingerprints are shown.",
	qrTitle: "QR code",
	qrLead: "The code is read on this phone. A link is checked here and is not opened.",
	qrStart: "Start camera",
	qrStop: "Stop",
	qrEmpty: "No QR code in view.",
	qrAgain: "Scan again",
	weekTitle: "This week",
	weekMessages: "Suspicious messages",
	weekLinks: "Suspicious links",
	weekPhones: "Suspicious numbers",
	weekExport: "Export this week",
	numbersExport: "Export the book",
	numbersImport: "Import a book",
	numbersImported: "The book was merged on this phone.",
	numbersBad: "That file is not a Kanaf number book.",
	advisorStale: "Signature databases are more than seven days old.",
	advisorPending: "Items are waiting for your decision.",
	advisorLive: "Real-time protection is off.",
	advisorNotify: "Notifications are blocked, so Kanaf cannot alert you.",
	advisorInsecure: "This page is not in a secure context.",
	unavailable: "Cannot be checked here",
	lock: "Screen lock",
	patch: "Security patch level",
	usb: "USB debugging",
	developer: "Developer options",
	unavailableBody: "These checks need the Android system. This browser cannot read them, and Kanaf will not invent a result.",
	limitsTitle: "Protection limits",
	limit1: "Kanaf cannot intercept every app launch or every file write. Android does not allow that for a normal app, and a browser allows even less.",
	limit2: "Installed apps are not visible here. A scan covers the folder or files you choose.",
	limit3: "The inbox is not read. Paste or share the message text instead.",
	limit4: "Nothing is removed, quarantined, or blocked unless you choose that action.",
	limit5: "Scheduled scans run only while Kanaf is open.",
	limit6: "Engine body signatures (ndb, ldb, bytecode) are not used, because that would require libclamav.",
	limit7: "The main ClamAV hash set is filtered to Android, Java, script, archive, and document families. The daily hash set is loaded in full.",
	privacyTitle: "Privacy",
	privacy1: "Files, messages, links, and fingerprints stay on this device. They are not uploaded.",
	privacy2: "The only network use is downloading public signature databases, and only when you ask.",
	privacy3: "The vault uses AES-GCM. The key is non-exportable and stays in this browser.",
	privacy4: "Quarantine names are random. Message text is not kept.",
	networkTitle: "Network options",
	logTitle: "Scan log",
	scheduleTitle: "Scheduled scan",
	foldersTitle: "Watched folders",
	files: "files",
	findings: "findings",
	skipped: "skipped as too large",
	modeDeep: "Deep",
	modeQuick: "Quick",
	modeCustom: "Custom",
	modeScheduled: "Scheduled",
	modeLive: "Real-time",
	save: "Save",
	domains: "Official domains",
	resetSenders: "Reset senders",
	linkInvalid: "Enter a valid http or https address.",
	working: "Analyzing",
	confirm: "Confirm",
	close: "Close",
	yesDelete: "Delete",
	allowAddress: "Allow this address",
	linkNoVault: "A link is not a file, so it cannot be quarantined or deleted from a device.",
	messageNoDelete: "The message text was not stored and the inbox was not opened, so there is nothing to delete.",
	bytes: "Size",
	path: "Path",
	fingerprint: "Fingerprint",
	sourceTerms: "Terms",
	reported: "The CVD also contains other signature types that Kanaf does not load.",
	progressOf: "Progress",
	grant: "Kanaf needs the folder you want scanned.",
	nothing: "No file was selected.",
	livePick: "Choose the folder to watch.",
	stopLive: "Real-time protection is off. The notice is gone.",
	cellularBlocked: "Update is waiting for Wi-Fi, as you asked.",
	updateFail: "A source failed. The others were kept.",
	cloudHonest: "An update downloads these lists from their publishers. Kaspersky's database is not public, so it cannot be added. ClamAV's daily file reports about 356,000 signatures of every type; Kanaf keeps file hashes, not bytecode rules. No model uploads the file or the message.",
	numbersTitle: "Official numbers",
	numbersLead: "Add a number only after you have checked it on the bank's or the company's own site. A confirmed number is not treated as a callback lure. A blocked number is refused if Kanaf is the call-screening app.",
	numberLabel: "Name",
	numberAdd: "Confirm number",
	blockAdd: "Block number",
	numberRemove: "Remove",
	numberBad: "That is not a phone number.",
	callTitle: "Live call screening",
	callLead: "Android allows this only after you choose Kanaf as the call-screening app. It can refuse a premium-rate number or a number you blocked. It does not see the conversation.",
	callAsk: "Choose Kanaf for call screening",
	callOn: "Call screening is on.",
	callOff: "Call screening is off.",
	callOld: "This phone's Android is too old for the call-screening role.",
	cleanTitle: "Clean up",
	cleanLead: "Android does not let an ordinary app wipe other apps' cache by itself. The first button opens the system screen when this phone has one. Otherwise pick an app and use Clear cache on its system page. Temporary files need access to shared storage, which you grant yourself.",
	cleanApps: "Clear app cache",
	cleanAppsNote: "Android's cache screen is open. Confirm there.",
	cleanAppsFail: "This phone has no single cache screen. Pick an app. Its system page has Clear cache.",
	cleanTemp: "Cache and temporary files",
	cleanNeedFiles: "Allow access to all files, then come back and press the button again. Only junk names are listed.",
	cleanOpen: "Open",
	cleanOwn: "Clear Kanaf cache",
	cleanFreed: "Temporary files removed.",
	cleanJunk: "Look for unfinished downloads",
	cleanNone: "No unfinished download was found.",
	cleanDelete: "Delete",
	cleanWeb: "This cleanup runs on the phone.",
	exportDecisions: "Export decisions",
	exported: "Saved in Downloads as kanaf-decisions.txt. Nothing was uploaded.",
	exportEmpty: "There is no decision to export yet.",
	deviceTitle: "Device",
	devicePageLead: "Read from this phone, left to right. Battery capacity is an estimate. A factory date appears only when the radio firmware publishes one. Otherwise the date is the system image.",
	updateOk: "Databases were refreshed.",
	connectionUnknown: "This browser does not say whether the connection is metered.",
	selfTest: "Detection self-test",
	chargingSkip: "Skipped because the device is not charging.",
	statusIdle: "Idle",
	statusRunning: "Running",
	statusDone: "Finished",
	statusCancelled: "Cancelled",
	removeFolder: "Stop watching",
	vaultHelp: "Items here are encrypted. Restore downloads the original file.",
	decisionTitle: "Your decision",
	waiting: "Waiting for a valid link",
	on: "On",
	off: "Off",
	recommendations: "Recommendations",
	openSettings: "Open system settings",
	cannotChange: "Kanaf does not change device settings by itself.",
	nameField: "Display name",
	domainField: "Domain",
	saved: "Saved",
	scanDoneClean: "No known threats were found.",
	includeDetail: "Detail",
	ariaShield: "Kanaf shield",
	ariaSwitch: "Real-time protection",
	homeLead: "Home",
	scanFolder: "Scan a folder",
	liveAndroid: "Watching new installs and downloads. Nothing is blocked or removed unless you decide.",
	connectionWifi: "Connected over Wi-Fi.",
	connectionCell: "Connected over mobile data.",
	connectionNone: "No network connection.",
	lockOn: "Screen lock is on.",
	lockOff: "Screen lock is off.",
	usbOn: "USB debugging is on.",
	usbOff: "USB debugging is off.",
	devOn: "Developer options are on.",
	devOff: "Developer options are off.",
	limitApp1: "Kanaf cannot intercept every app launch or every file write. Android does not allow that for a normal app. While real-time protection is on, new installs and new downloads are reported for your decision.",
	limitApp2: "A device scan reads user-installed apps and the downloads Android exposes to Kanaf. Preinstalled system apps are not opened. You can also scan a folder you choose.",
	limitApp5: "A scheduled scan starts when you open Kanaf, if it is due. Android does not let a normal app keep scanning after you leave.",
	privacyApp: "The vault uses AES-GCM. The key is non-exportable and stays on this device.",
	uninstallAsked: "The system uninstall screen is open. Kanaf removes nothing until you confirm there.",
	updating: "Updating databases",
	realtimeFail: "Real-time protection did not start. Allow notifications. Android can also stop the watcher if Kanaf is force-closed.",
	deviceLead: "Read from this device. Kanaf does not change these settings.",
	downloadsClosed: "Downloads were not readable. Use folder scan for that directory.",
	deviceHint: "Deep and quick scans check installed apps on this device, plus downloads when Android allows it."
};
var ar = {
	name: "كنف",
	tagline: "افحص جهازك والقرار لك",
	engineLocal: "بصمات محلية",
	engineBehavior: "سلوك على الجهاز",
	engineCloud: "قواعد سحابية",
	cloudHint: "فحص الجهاز يحدّث قواعد البصمات إذا مرّ عليها يوم. الملفات تبقى هنا، ولا يُرفع شيء إلى رمل سحابي.",
	integrityBad: "هذه النسخة من كنف مُعدَّلة. تحديث القواعد موقوف.",
	behaviorRev: "نموذج السلوك ٣",
	behaviorLead: "يقرأ الصلاحيات والخدمات المُعلَنة. لا يراقب الشاشة ولا الكتابة. الإصابة تحتاج زوجًا قويًا، مثل نافذة فوق التطبيقات مع خدمة إمكانية الوصول، أو رسائل SMS بلا أيقونة تشغيل. تطبيقات المتاجر المعروفة تُستثنى. الإصابة اشتباه وليست إدانة.",
	behaviorScan: "فحص سلوك التطبيقات",
	behaviorEmpty: "لا تطبيق مثبّت طابق قواعد السلوك القوية.",
	behaviorFail: "تعذرت قراءة التطبيقات. أعد المحاولة.",
	behaviorWeb: "هذا الفحص يعمل على الهاتف حيث تُقرأ صلاحيات التطبيقات.",
	phishTitle: "حماية من التصيّد",
	phishLead: "يبقى العنوان أو الرقم على الجهاز. تقدير محلي قابل للتفسير يطابق قوائم التصيّد، والعلامات المقلَّدة، والوجهة المخفية، والاسم المزروع، وأرقام الأقساط الدولية، وطلب الاتصال برقم شخصي. لا يُرفع شيء، ولا يُفتح الرابط.",
	phishClip: "فحص النص المنسوخ",
	phishEmptyClip: "لا رابط ولا رقم هاتف في هذا النص.",
	phonePremium: "رقم قسط دولي يُستخدم في احتيال الاتصال العكسي. لا تتصل به.",
	phoneLure: "الرسالة تطلب الاتصال برقم شخصي وهي تتحدث عن بنك أو رمز أو حساب. الإشعار الرسمي يستخدم رمزًا قصيرًا لا جوالًا خاصًا.",
	userinfo: "ما قبل علامة @ ليس الموقع الحقيقي. الوجهة هي العنوان بعده.",
	brandHost: "اسم بنك أو خدمة معروفة يظهر داخل موقع مختلف.",
	macro: "المستند فيه ماكرو. الماكرو يمكنه تشغيل أوامر عند فتح الملف.",
	docLink: "المستند يشير إلى رابط مصنّف أو مشبوه.",
	polyglot: "بيانات ملحقة بعد نهاية الصورة. الصورة لا تحتاج برنامجًا في ذيلها.",
	pdfLaunch: "ملف PDF يطلب تشغيل برنامج آخر.",
	pdfActive: "ملف PDF يشغّل نصًا برمجيًا عند فتحه.",
	fileReport: "نتيجة الملف",
	fileLead: "كل ملف تُحسب بصمته على الجهاز. يُفتح zip وملفات أوفيس. الصور لا تُعرَف بالنظر. RAR يُعرَف وتُحسب بصمته ولا يُفك ضغطه. النتيجة النظيفة نتيجة.",
	fileClean: "لا تهديد معروف في هذا الملف.",
	fileSkipped: "الملف أكبر من الحد أو تعذرت قراءته.",
	kindApk: "حزمة أندرويد: بصمة، شهادة، صلاحيات، وملفات داخلية.",
	kindZip: "أرشيف zip: تُفحص الملفات الداخلية. المشفّر يُتخطى.",
	kindOffice: "مستند أوفيس: ماكرو، برامج مضمّنة، وروابط خطرة.",
	kindImage: "صورة: بصمة وذيل ملحق بعدها. لا يوجد تعرّف بصري.",
	kindPdf: "PDF: بصمة، مع التشغيل التلقائي والنصوص عند الفتح.",
	kindRar: "RAR: يُعرَف وتُحسب بصمته. المحتوى المضغوط لا يُفك.",
	kindOle: "أوفيس قديم: بصمة، مع البحث عن مخزن ماكرو.",
	kindOther: "هذا النوع تُحسب بصمته فقط ولا يُفك.",
	notices: "معاينات إشعارات التطبيقات",
	noticesLead: "بهذا الإذن يقرأ كنف المعاينة فقط إذا كان فيها رابط، يفحص الرابط، ولا يحتفظ بنص الرسالة. إذا أخفى واتساب المعاينة فلا يمكن قراءتها.",
	noticesOpen: "فتح إذن الإشعارات",
	noticesOn: "إذن الإشعارات مفعّل.",
	noticesOff: "إذن الإشعارات غير مفعّل.",
	lang: "EN",
	scanDeep: "فحص عميق للجهاز",
	scanQuick: "فحص سريع",
	results: "النتائج",
	paste: "رابط أو رقم أو نص الرسالة",
	scanLink: "فحص",
	messages: "فحص رسائل الجهاز",
	homeMsg: "الرسائل",
	addFile: "فحص ملف أو مستند",
	homeFile: "فحص ملف",
	update: "تحديث قواعد البيانات",
	homeUpdate: "القواعد",
	realtime: "الحماية الفورية",
	advisor: "مستشار الأمان",
	homeAdvisor: "المستشار",
	settings: "الإعدادات",
	back: "رجوع",
	resultsTitle: "نتائج الفحص",
	decide: "اتخذ القرار",
	allow: "السماح له بالعمل",
	quarantine: "نقله إلى الحجر الصحي",
	delete: "حذف من الجهاز",
	clean: "لم تُكتشف تهديدات معروفة.",
	preparing: "جارٍ تجهيز قواعد البيانات",
	notReady: "القواعد غير جاهزة بعد",
	failedDb: "تعذّر تحميل القواعد",
	retry: "إعادة المحاولة",
	cancel: "إلغاء",
	listing: "جارٍ تعداد الملفات",
	scanning: "جارٍ الفحص",
	linkTitle: "فحص الرابط",
	noIndicators: "لا مؤشرات",
	suspicious: "مشبوه",
	malicious: "معروف بأنه خبيث",
	open: "فتح",
	confirmOpen: "فتح هذا العنوان في علامة جديدة؟ لن يفتحه كنف حتى تؤكد.",
	expand: "توسيع التحويلات",
	expandWarn: "هذه الخطوة تتصل بالموقع من متصفحك وتكشف عنوانك. هي اختيارية.",
	expandFail: "منع المتصفح قراءة الوجهة. لم يُرسل العنوان إلى أي خادم.",
	messagesTitle: "فحص الرسائل",
	sender: "المرسل",
	message: "الرسالة",
	analyze: "فحص الرسالة",
	notStored: "لا يُخزَّن نص الصندوق. يُحفظ المرسل والسبب والبصمة للرسالة المشبوهة فقط.",
	scanInbox: "فحص صندوق الرسائل",
	inboxHint: "يقرأ رسائل SMS ووسائط MMS التي يتيحها أندرويد، والروابط والمرفقات داخلها. واتساب وتيليجرام غير مقروءين. لا تُعرض رسالة إلا إذا احتوت رابطًا خبيثًا معروفًا، أو رابطًا يشبه علامة رسمية، أو عنوان IP عامًا، أو مرفقًا مطابقًا لبصمة خبيثة.",
	inboxEmpty: "لا رسائل مشبوهة في الصندوق.",
	inboxDenied: "رُفض إذن الرسائل. لم يُقرأ شيء.",
	inboxWeb: "المتصفح لا يقرأ صندوق الهاتف. ألصق رسالة واحدة في الأسفل.",
	inboxProgress: "جارٍ فحص الرسائل",
	trusted: "مرسلون موثوقون",
	addSender: "إضافة مرسل",
	quarantineTitle: "الحجر",
	vault: "في الحجر",
	allowed: "المسموح بها",
	restore: "استعادة",
	purge: "حذف نهائي",
	revoke: "إلغاء السماح",
	emptyVault: "الخزنة فارغة.",
	emptyAllow: "لا عناصر مسموحًا بها.",
	emptyResults: "لا عناصر بانتظار القرار.",
	advisorTitle: "مستشار الأمان",
	noAdvice: "لا توصيات الآن.",
	settingsTitle: "الإعدادات",
	schedule: "الفحص المجدول",
	folders: "مجلدات المراقبة",
	sources: "مصادر القواعد",
	log: "سجل الفحوصات",
	network: "خيارات الشبكة",
	limits: "حدود الحماية",
	privacy: "الخصوصية",
	wifiOnly: "تنزيل القواعد عبر الواي فاي فقط",
	cellularWarn: "يبدو الاتصال محدود البيانات. حجم القواعد كبير.",
	downloadAnyway: "التنزيل عبر هذا الاتصال",
	sourcesTitle: "مصادر القواعد",
	license: "الترخيص",
	count: "العدد",
	updated: "آخر تحديث",
	version: "الإصدار",
	notLoaded: "لم تُحمَّل",
	downloading: "جارٍ التنزيل",
	ready: "جاهزة",
	failed: "فشل",
	logEmpty: "لا فحوصات بعد.",
	foldersEmpty: "لا مجلدات تحت المراقبة.",
	addFolder: "اختيار مجلد",
	remove: "إزالة",
	daily: "يوميًا",
	weekly: "أسبوعيًا",
	charging: "أثناء الشحن فقط",
	scheduleHelp: "يعمل الفحص بينما كنف مفتوح. المتصفح لا يواصل الفحص بعد المغادرة.",
	enable: "مفعّل",
	notifyAsk: "يستطيع كنف تنبيهك عندما ينتظر عنصر قرارك.",
	enableNotify: "السماح بالإشعارات",
	realtimeNeed: "بانتظار صلاحية الإشعارات.",
	realtimeMissing: "هذا المتصفح لا يراقب المجلد دون استطلاع متواصل، لذلك تبقى الحماية الفورية متوقفة.",
	liveWatching: "تُراقب المجلد الذي اخترته.",
	confirmDelete: "حذف هذا الملف من الجهاز؟",
	confirmVault: "نقل نسخة إلى الخزنة المشفّرة؟",
	confirmPurge: "حذف هذا العنصر من الخزنة نهائيًا؟",
	confirmRestore: "استعادة هذا الملف؟ سيُنزَّل إلى جهازك.",
	deleteBlocked: "لم يمنح المتصفح صلاحية الحذف. الملف ما زال في مكانه.",
	originalRemains: "الملف الأصلي ما زال في مكانه لأن الحذف لم يُمنح. الخزنة تحتفظ بنسخة مشفّرة.",
	moved: "الملف في الخزنة المشفّرة.",
	allowedDone: "مسموح. سيُتخطى في الفحوصات اللاحقة.",
	eicar: "تشغيل اختبار EICAR",
	eicarHelp: "يمرّر ملف الاختبار القياسي ذي 68 بايتًا عبر المحرك الحقيقي. ليس فيروسًا.",
	eicarHit: "اكتُشف ملف اختبار EICAR.",
	eicarMiss: "لم يُكتشف ملف الاختبار. قد تكون القواعد ناقصة.",
	permissions: "الصلاحيات",
	noPerms: "لم تُستخرج صلاحيات.",
	reason: "السبب",
	hashMatch: "يطابق الملف بصمة معروفة.",
	eicarReason: "هذا ملف اختبار EICAR. خط الكشف يعمل.",
	badCert: "شهادة التوقيع ضمن قائمة شهادات برمجيات خبيثة معروفة.",
	heuristic: "مؤشرات ساكنة تبدو مريبة. هذا ليس حكمًا بالإدانة.",
	archiveDepth: "الأرشيف أعمق من الحد الآمن، فلم تُفتح المستويات الداخلية.",
	zipLimit: "بلغ الأرشيف حدًا وقائيًا ولم يُفتح بالكامل.",
	zipCorrupt: "تعذّرت قراءة الأرشيف كاملًا.",
	listed: "العنوان ضمن قائمة روابط خبيثة محمّلة.",
	ipHost: "المضيف عنوان IP مباشر.",
	shortener: "هذا مختصِر روابط، فالوجهة مخفية.",
	punycode: "المضيف يستخدم بوني كود.",
	lookalike: "الاسم يشبه",
	lureModel: "نموذج الصياغة علّم هذه الجملة:",
	cloudLure: "النموذج السحابي، وقد رأى هذا النص فقط، علّم:",
	cloudSend: "إرسال هذا النص إلى السحابة",
	cloudLead: "يُرسَل النص المكتوب في المربع فقط. الملفات وبقية الرسائل تبقى على الهاتف.",
	cloudKey: "مفتاح سحابي، يُحفظ على هذا الهاتف",
	cloudNeed: "لا مفتاح سحابي محفوظ، فلم يُرسَل شيء.",
	cloudClean: "النموذج السحابي لم يعلّم هذا النص.",
	readImage: "قراءة صورة",
	readLead: "يُقرأ النص من الصورة على هذا الهاتف ثم يُفحص. الصورة لا تُرفع.",
	readEmpty: "لم يُقرأ نص من الصورة.",
	readFail: "تعذرت قراءة الصورة على هذا الجهاز.",
	offDomain: "اسم المرسل يطابق مرسلًا موثوقًا، لكن أحد الروابط خارج نطاقاته.",
	overlay: "يطلب تراكب الشاشة مع خدمة وصول.",
	smsNet: "يطلب قراءة الرسائل أو استقبالها مع الإنترنت.",
	admin: "يطلب صلاحية مدير الجهاز.",
	launcher: "لا أيقونة تشغيل، مع مكوّن يعمل في الخلفية.",
	dynamic: "يحمّل الشفرة ديناميكيًا ويبدو مشوَّشًا.",
	packer: "يحوي أداة تغليف معروفة.",
	testKey: "موقَّع بمفتاح اختبار أو تصحيح.",
	installNet: "يستطيع طلب تثبيت تطبيقات واستخدام الإنترنت.",
	dexSms: "الكود يرسل رسائل ويستخدم خدمة إمكانية الوصول.",
	hideIcon: "الكود يستطيع إخفاء أيقونته، مع استخدام الرسائل أو إمكانية الوصول.",
	dexAdmin: "الكود يطلب أن يصبح مديرًا للجهاز.",
	smsAccess: "يطلب قراءة الرسائل وخدمة إمكانية الوصول.",
	smsOverlay: "يطلب قراءة الرسائل والرسم فوق الشاشات.",
	certChanged: "تغيّرت شهادة التوقيع بعد تحديث. البصمة السابقة والحالية معروضتان.",
	qrTitle: "رمز QR",
	qrLead: "يُقرأ الرمز على هذا الهاتف. الرابط يُفحص هنا ولا يُفتح.",
	qrStart: "تشغيل الكاميرا",
	qrStop: "إيقاف",
	qrEmpty: "لا رمز في الإطار.",
	qrAgain: "فحص مرة أخرى",
	weekTitle: "هذا الأسبوع",
	weekMessages: "رسائل مشبوهة",
	weekLinks: "روابط مشبوهة",
	weekPhones: "أرقام مشبوهة",
	weekExport: "تصدير الأسبوع",
	numbersExport: "تصدير الدفتر",
	numbersImport: "استيراد دفتر",
	numbersImported: "دُمج الدفتر على هذا الهاتف.",
	numbersBad: "هذا الملف ليس دفتر أرقام كنف.",
	advisorStale: "مضى على قواعد البيانات أكثر من سبعة أيام.",
	advisorPending: "عناصر تنتظر قرارك.",
	advisorLive: "الحماية الفورية متوقفة.",
	advisorNotify: "الإشعارات محظورة، فلا يستطيع كنف تنبيهك.",
	advisorInsecure: "هذه الصفحة ليست في سياق آمن.",
	unavailable: "لا يمكن التحقق هنا",
	lock: "قفل الشاشة",
	patch: "مستوى تحديث الأمان",
	usb: "تصحيح USB",
	developer: "خيارات المطوّر",
	unavailableBody: "هذه الفحوصات تحتاج نظام أندرويد. المتصفح لا يقرأها، وكنف لا يخترع نتيجة.",
	limitsTitle: "حدود الحماية",
	limit1: "لا يستطيع كنف اعتراض كل تشغيل تطبيق ولا كل كتابة ملف. أندرويد لا يسمح بذلك لتطبيق عادي، والمتصفح يسمح بأقل من ذلك.",
	limit2: "التطبيقات المثبتة غير ظاهرة هنا. الفحص يغطي المجلد أو الملفات التي تختارها.",
	limit3: "صندوق الوارد لا يُقرأ. ألصق نص الرسالة أو شاركه.",
	limit4: "لا يُحذف شيء ولا يُحجر ولا يُمنع إلا إذا اخترت ذلك.",
	limit5: "الفحص المجدول يعمل فقط بينما كنف مفتوح.",
	limit6: "لا تُستخدم توقيعات جسم الملف (ndb وldb وbytecode) لأنها تتطلب libclamav.",
	limit7: "مجموعة بصمات ClamAV الرئيسية مُرشَّحة لعائلات أندرويد وجافا والسكربتات والأرشيفات والمستندات. المجموعة اليومية محمّلة كاملة.",
	privacyTitle: "الخصوصية",
	privacy1: "تبقى الملفات والرسائل والروابط والبصمات على هذا الجهاز. لا تُرفع.",
	privacy2: "الاستخدام الشبكي الوحيد هو تنزيل قواعد البيانات العامة، وعند طلبك فقط.",
	privacy3: "الخزنة تستخدم AES-GCM. المفتاح غير قابل للتصدير ويبقى في هذا المتصفح.",
	privacy4: "أسماء الحجر عشوائية. نص الرسالة لا يُحفظ.",
	networkTitle: "خيارات الشبكة",
	logTitle: "سجل الفحوصات",
	scheduleTitle: "الفحص المجدول",
	foldersTitle: "مجلدات المراقبة",
	files: "ملفات",
	findings: "نتائج",
	skipped: "تُخطّي لكبر الحجم",
	modeDeep: "عميق",
	modeQuick: "سريع",
	modeCustom: "مخصص",
	modeScheduled: "مجدول",
	modeLive: "فوري",
	save: "حفظ",
	domains: "النطاقات الرسمية",
	resetSenders: "إعادة المرسلين",
	linkInvalid: "أدخل عنوان http أو https صالحًا.",
	working: "جارٍ التحليل",
	confirm: "تأكيد",
	close: "إغلاق",
	yesDelete: "حذف",
	allowAddress: "السماح لهذا العنوان",
	linkNoVault: "الرابط ليس ملفًا، فلا يُحجر ولا يُحذف من جهاز.",
	messageNoDelete: "لم يُخزَّن نص الرسالة ولم يُفتح صندوق الوارد، فلا يوجد ما يُحذف.",
	bytes: "الحجم",
	path: "المسار",
	fingerprint: "البصمة",
	sourceTerms: "الشروط",
	reported: "يحوي ملف CVD أنواع توقيع أخرى لا يحمّلها كنف.",
	progressOf: "التقدم",
	grant: "يحتاج كنف إلى المجلد الذي تريد فحصه.",
	nothing: "لم يُختر ملف.",
	livePick: "اختر المجلد المراد مراقبته.",
	stopLive: "الحماية الفورية متوقفة. أُزيل التنبيه.",
	cellularBlocked: "التحديث ينتظر الواي فاي كما طلبت.",
	updateFail: "فشل مصدر. أُبقيت بقية المصادر.",
	cloudHonest: "التحديث ينزّل هذه القوائم من ناشرها. قاعدة كاسبرسكي ليست عامة ولا يمكن إضافتها. ملف ClamAV اليومي يعلن نحو 356 ألف توقيع من كل الأنواع؛ كنف يحتفظ ببصمات الملفات لا بقواعد البايتكود. لا يوجد نموذج يرفع الملف أو الرسالة.",
	numbersTitle: "أرقام رسمية",
	numbersLead: "أضف الرقم فقط بعد أن تتثبّت منه في موقع البنك أو الشركة. الرقم الذي تؤكده لا يُعامل كطلب اتصال احتيالي. الرقم المحظور يُرفض إذا جعلت كنف تطبيق فرز المكالمات.",
	numberLabel: "الاسم",
	numberAdd: "تأكيد الرقم",
	blockAdd: "حظر الرقم",
	numberRemove: "إزالة",
	numberBad: "هذا ليس رقم هاتف.",
	callTitle: "فرز المكالمة",
	callLead: "أندرويد يسمح بهذا فقط بعد أن تختار كنف تطبيق فرز المكالمات. يستطيع رفض رقم القسط الدولي أو رقمًا حظرته. لا يسمع المحادثة.",
	callAsk: "اختيار كنف لفرز المكالمات",
	callOn: "فرز المكالمات مفعّل.",
	callOff: "فرز المكالمات متوقف.",
	callOld: "نسخة أندرويد على هذا الهاتف أقدم من دور فرز المكالمات.",
	cleanTitle: "تنظيف",
	cleanLead: "أندرويد لا يسمح لتطبيق عادي بمسح كاش التطبيقات الأخرى من داخل نفسه. الزر الأول يفتح شاشة النظام إن وُجدت على هذا الهاتف. وإلا اختر التطبيق، وصفحته في النظام فيها مسح الكاش. الملفات المؤقتة تحتاج إذن الوصول إلى كل الملفات، وتمنحه أنت.",
	cleanApps: "مسح كاش التطبيقات",
	cleanAppsNote: "فُتحت شاشة كاش أندرويد. أكّد هناك.",
	cleanAppsFail: "هذا الهاتف لا يملك شاشة كاش واحدة. اختر التطبيق. صفحته في النظام فيها مسح الكاش.",
	cleanTemp: "الكاش والملفات المؤقتة",
	cleanNeedFiles: "اسمح بالوصول إلى كل الملفات، ثم ارجع واضغط الزر مرة أخرى. لا تُعرض إلا أسماء الجنك.",
	cleanOpen: "فتح",
	cleanOwn: "مسح كاش كنف",
	cleanFreed: "أُزيلت الملفات المؤقتة.",
	cleanJunk: "البحث عن تنزيلات ناقصة",
	cleanNone: "لا ملف تنزيل ناقص.",
	cleanDelete: "حذف",
	cleanWeb: "هذا التنظيف يعمل على الهاتف.",
	exportDecisions: "تصدير القرارات",
	exported: "حُفظ في التنزيلات باسم kanaf-decisions.txt. لم يُرفع شيء.",
	exportEmpty: "لا قرار للتصدير بعد.",
	deviceTitle: "الجهاز",
	devicePageLead: "تُقرأ من هذا الهاتف من اليسار. سعة البطارية تقدير. تاريخ المصنع يظهر فقط إذا نشره برنامج الراديو، وإلا فالتاريخ هو بناء النظام.",
	updateOk: "تم تحديث القواعد.",
	connectionUnknown: "هذا المتصفح لا يوضّح إن كان الاتصال محدود البيانات.",
	selfTest: "اختبار خط الكشف",
	chargingSkip: "تُخطّي لأن الجهاز لا يشحن.",
	statusIdle: "خامل",
	statusRunning: "جارٍ",
	statusDone: "اكتمل",
	statusCancelled: "أُلغي",
	removeFolder: "إيقاف المراقبة",
	vaultHelp: "العناصر هنا مشفّرة. الاستعادة تنزّل الملف الأصلي.",
	decisionTitle: "قرارك",
	waiting: "بانتظار رابط صالح",
	on: "تشغيل",
	off: "إيقاف",
	recommendations: "التوصيات",
	openSettings: "فتح إعدادات النظام",
	cannotChange: "كنف لا يغيّر إعدادات الجهاز بنفسه.",
	nameField: "الاسم الظاهر",
	domainField: "النطاق",
	saved: "حُفظ",
	scanDoneClean: "لم تُكتشف تهديدات معروفة.",
	includeDetail: "التفصيل",
	ariaShield: "درع كنف",
	ariaSwitch: "الحماية الفورية",
	homeLead: "الرئيسية",
	scanFolder: "فحص مجلد",
	liveAndroid: "تُراقَب التثبيتات الجديدة والتنزيلات. لا يُحظر شيء ولا يُحذف إلا بقرارك.",
	connectionWifi: "متصل عبر الواي فاي.",
	connectionCell: "متصل عبر بيانات الجوال.",
	connectionNone: "لا يوجد اتصال بالشبكة.",
	lockOn: "قفل الشاشة مفعّل.",
	lockOff: "قفل الشاشة غير مفعّل.",
	usbOn: "تصحيح USB مفعّل.",
	usbOff: "تصحيح USB متوقف.",
	devOn: "خيارات المطوّر مفعّلة.",
	devOff: "خيارات المطوّر متوقفة.",
	limitApp1: "لا يستطيع كنف اعتراض كل تشغيل تطبيق ولا كل كتابة ملف. أندرويد لا يسمح بذلك لتطبيق عادي. مع الحماية الفورية تُعرض التثبيتات والتنزيلات الجديدة لتقرر أنت.",
	limitApp2: "فحص الجهاز يقرأ التطبيقات التي ثبّتها أنت والتنزيلات التي يتيحها أندرويد. تطبيقات النظام المسبقة التثبيت لا تُفتح. ويمكنك أيضًا فحص مجلد تختاره.",
	limitApp5: "الفحص المجدول يبدأ عند فتح كنف إذا حان موعده. أندرويد لا يسمح لتطبيق عادي بمواصلة الفحص بعد المغادرة.",
	privacyApp: "الخزنة تستخدم AES-GCM. المفتاح غير قابل للتصدير ويبقى على هذا الجهاز.",
	uninstallAsked: "فُتحت شاشة إزالة التثبيت في النظام. كنف لا يزيل شيئًا حتى تؤكد هناك.",
	updating: "جارٍ تحديث القواعد",
	realtimeFail: "لم تبدأ الحماية الفورية. اسمح بالإشعارات. وقد يوقفها أندرويد إذا أُغلق كنف بالقوة.",
	deviceLead: "قُرئت من هذا الجهاز. كنف لا يغيّر هذه الإعدادات.",
	downloadsClosed: "تعذّرت قراءة التنزيلات. استخدم فحص المجلد لذلك الدليل.",
	deviceHint: "الفحص العميق والسريع يفحصان التطبيقات المثبتة على هذا الجهاز، والتنزيلات حين يسمح أندرويد."
};
var signatureForms = {
	ar: {
		zero: "لا بصمات محمّلة",
		one: "بصمة واحدة محمّلة",
		two: "بصمتان محملتان",
		few: "{n} بصمات محمّلة",
		many: "{n} بصمة محمّلة",
		other: "{n} بصمة محمّلة"
	},
	en: {
		zero: "No signatures loaded",
		one: "1 signature loaded",
		two: "{n} signatures loaded",
		few: "{n} signatures loaded",
		many: "{n} signatures loaded",
		other: "{n} signatures loaded"
	}
};
var resultForms = {
	ar: {
		zero: "النتائج",
		one: "النتائج ({n})",
		two: "النتائج ({n})",
		few: "النتائج ({n})",
		many: "النتائج ({n})",
		other: "النتائج ({n})"
	},
	en: {
		zero: "Results",
		one: "Results ({n})",
		two: "Results ({n})",
		few: "Results ({n})",
		many: "Results ({n})",
		other: "Results ({n})"
	}
};
var adviceForms = {
	ar: {
		zero: "لا توصيات الآن.",
		one: "توصية واحدة",
		two: "توصيتان",
		few: "{n} توصيات",
		many: "{n} توصية",
		other: "{n} توصية"
	},
	en: {
		zero: "No recommendations right now.",
		one: "1 recommendation",
		two: "{n} recommendations",
		few: "{n} recommendations",
		many: "{n} recommendations",
		other: "{n} recommendations"
	}
};
function formOf(n) {
	const abs = Math.abs(Math.trunc(n));
	if (abs === 0) return "zero";
	if (abs === 1) return "one";
	if (abs === 2) return "two";
	const mod = abs % 100;
	if (mod >= 3 && mod <= 10) return "few";
	if (mod >= 11 && mod <= 99) return "many";
	return "other";
}
function formatCount(locale, n) {
	return new Intl.NumberFormat("en-US").format(n);
}
function plural(locale, n, forms) {
	const key = locale === "ar" ? formOf(n) : n === 1 ? "one" : "other";
	return forms[locale][key].replace("{n}", formatCount(locale, n));
}
function behaviorResult(locale, scanned, hits) {
	if (locale === "ar") return hits > 0 ? `فُحص ${scanned} تطبيقًا، وظهر ${hits} بنمط قوي.` : `فُحص ${scanned} تطبيقًا. لا نمط سلوك قوي.`;
	return hits > 0 ? `Checked ${scanned} apps. ${hits} matched a strong pattern.` : `Checked ${scanned} apps. No strong behavior pattern.`;
}
function signatureLabel(locale, n) {
	return plural(locale, n, signatureForms);
}
function resultsLabel(locale, n) {
	return plural(locale, n, resultForms);
}
function adviceLabel(locale, n) {
	return plural(locale, n, adviceForms);
}
var cleanScanForms = {
	ar: {
		zero: "لم يُفحص أي ملف.",
		one: "فُحص ملف واحد. لم تُكتشف تهديدات معروفة.",
		two: "فُحص ملفان. لم تُكتشف تهديدات معروفة.",
		few: "فُحصت {n} ملفات. لم تُكتشف تهديدات معروفة.",
		many: "فُحص {n} ملفًا. لم تُكتشف تهديدات معروفة.",
		other: "فُحص {n} ملف. لم تُكتشف تهديدات معروفة."
	},
	en: {
		zero: "No file was scanned.",
		one: "Scanned 1 file. No known threats were found.",
		two: "Scanned {n} files. No known threats were found.",
		few: "Scanned {n} files. No known threats were found.",
		many: "Scanned {n} files. No known threats were found.",
		other: "Scanned {n} files. No known threats were found."
	}
};
function scanSummary(locale, files) {
	return plural(locale, files, cleanScanForms);
}
var LocaleContext = (0, import_react.createContext)(null);
function detectLocale() {
	if (typeof window === "undefined") return "en";
	const saved = window.localStorage.getItem("kanaf-locale");
	if (saved === "ar" || saved === "en") return saved;
	return window.navigator.language.toLowerCase().startsWith("ar") ? "ar" : "en";
}
function LocaleProvider({ children }) {
	const [locale, setLocaleState] = (0, import_react.useState)("en");
	(0, import_react.useEffect)(() => {
		setLocaleState(detectLocale());
	}, []);
	(0, import_react.useEffect)(() => {
		document.documentElement.lang = locale;
		document.documentElement.dir = locale === "ar" ? "rtl" : "ltr";
	}, [locale]);
	const value = (0, import_react.useMemo)(() => {
		const setLocale = (next) => {
			window.localStorage.setItem("kanaf-locale", next);
			setLocaleState(next);
		};
		return {
			locale,
			t: locale === "ar" ? ar : en,
			setLocale,
			toggle: () => setLocale(locale === "ar" ? "en" : "ar")
		};
	}, [locale]);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(LocaleContext.Provider, {
		value,
		children
	});
}
function useI18n() {
	const ctx = (0, import_react.useContext)(LocaleContext);
	if (!ctx) throw new Error("locale");
	return ctx;
}
/** Keep static fetches on the preview prefix the proxy expects. */
function assetUrl(path) {
	const normalized = path.startsWith("/") ? path : `/${path}`;
	if (typeof window === "undefined") return normalized;
	const prefix = previewPathPrefix(window.location.hostname, window.location.pathname);
	return prefix ? `${prefix}${normalized}` : normalized;
}
var S = [
	7,
	12,
	17,
	22,
	7,
	12,
	17,
	22,
	7,
	12,
	17,
	22,
	7,
	12,
	17,
	22,
	5,
	9,
	14,
	20,
	5,
	9,
	14,
	20,
	5,
	9,
	14,
	20,
	5,
	9,
	14,
	20,
	4,
	11,
	16,
	23,
	4,
	11,
	16,
	23,
	4,
	11,
	16,
	23,
	4,
	11,
	16,
	23,
	6,
	10,
	15,
	21,
	6,
	10,
	15,
	21,
	6,
	10,
	15,
	21,
	6,
	10,
	15,
	21
];
var K$1 = /* @__PURE__ */ new Uint32Array(64);
for (let i = 0; i < 64; i++) K$1[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32);
function rotl(x, n) {
	return x << n | x >>> 32 - n;
}
/** Incremental MD5. Output is lowercase hex. */
var Md5 = class {
	a = 1732584193;
	b = 4023233417;
	c = 2562383102;
	d = 271733878;
	bytes = 0;
	buf = /* @__PURE__ */ new Uint8Array(64);
	len = 0;
	update(chunk) {
		this.bytes += chunk.length;
		let offset = 0;
		if (this.len > 0) {
			const need = 64 - this.len;
			const take = Math.min(need, chunk.length);
			this.buf.set(chunk.subarray(0, take), this.len);
			this.len += take;
			offset = take;
			if (this.len === 64) {
				this.block(this.buf);
				this.len = 0;
			}
		}
		while (offset + 64 <= chunk.length) {
			this.block(chunk.subarray(offset, offset + 64));
			offset += 64;
		}
		if (offset < chunk.length) {
			this.buf.set(chunk.subarray(offset), 0);
			this.len = chunk.length - offset;
		}
	}
	block(block) {
		const m = /* @__PURE__ */ new Uint32Array(16);
		for (let i = 0; i < 16; i++) {
			const j = i * 4;
			m[i] = block[j] | block[j + 1] << 8 | block[j + 2] << 16 | block[j + 3] << 24;
		}
		let a = this.a;
		let b = this.b;
		let c = this.c;
		let d = this.d;
		for (let i = 0; i < 64; i++) {
			let f = 0;
			let g = 0;
			if (i < 16) {
				f = b & c | ~b & d;
				g = i;
			} else if (i < 32) {
				f = d & b | ~d & c;
				g = (5 * i + 1) % 16;
			} else if (i < 48) {
				f = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			} else {
				f = c ^ (b | ~d);
				g = 7 * i % 16;
			}
			const next = a + f + K$1[i] + m[g] >>> 0;
			a = d;
			d = c;
			c = b;
			b = b + rotl(next, S[i]) >>> 0;
		}
		this.a = this.a + a >>> 0;
		this.b = this.b + b >>> 0;
		this.c = this.c + c >>> 0;
		this.d = this.d + d >>> 0;
	}
	digest() {
		const bits = this.bytes * 8;
		const pad = new Uint8Array(this.len < 56 ? 64 - this.len : 128 - this.len);
		pad[0] = 128;
		const view = new DataView(pad.buffer);
		view.setUint32(pad.length - 8, bits >>> 0, true);
		view.setUint32(pad.length - 4, Math.floor(bits / 2 ** 32), true);
		this.update(pad);
		const out = /* @__PURE__ */ new Uint8Array(16);
		const words = [
			this.a,
			this.b,
			this.c,
			this.d
		];
		for (let i = 0; i < 4; i++) {
			out[i * 4] = words[i] & 255;
			out[i * 4 + 1] = words[i] >>> 8 & 255;
			out[i * 4 + 2] = words[i] >>> 16 & 255;
			out[i * 4 + 3] = words[i] >>> 24 & 255;
		}
		return out;
	}
	hex() {
		return [...this.digest()].map((b) => b.toString(16).padStart(2, "0")).join("");
	}
};
function md5Hex(data) {
	const h = new Md5();
	h.update(data);
	return h.hex();
}
var N = BigInt("118640995551645342603070001658453189751527774412027743746599405743243142607464144767361060640655844749760788890022283424922762488917565551002467771109669598189410434699034532232228621591089508178591428456220796841621637175567590476666928698770143328137383952820383197532047771780196576957695822641224262693037");
var E = 100001027n;
var ALPH = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
var CvdError = class extends Error {
	code;
	constructor(code) {
		super(code);
		this.name = "CvdError";
		this.code = code;
	}
};
/**
* Legacy freshclam check: custom 6-bit alphabet, then p = c^e mod n,
* and the 16-byte result must equal the MD5 of the gzip body.
*/
function verifyClamAvDsig(md5HexDigest, dsig) {
	if (!/^[0-9a-f]{32}$/i.test(md5HexDigest) || dsig.length < 8) return false;
	let c = 0n;
	for (let i = 0; i < dsig.length; i++) {
		const dec = ALPH.indexOf(dsig[i]);
		if (dec < 0) return false;
		c += BigInt(dec) << BigInt(6) * BigInt(i);
	}
	const hex = modPow(c, E, N).toString(16).padStart(32, "0");
	if (hex.length > 32) return false;
	return hex === md5HexDigest.toLowerCase();
}
function modPow(base, exp, mod) {
	let result = 1n;
	let b = base % mod;
	let e = exp;
	while (e > 0n) {
		if (e & 1n) result = result * b % mod;
		b = b * b % mod;
		e >>= 1n;
	}
	return result;
}
function parseCvdHeader(file) {
	if (file.length < 520) throw new CvdError("bad-magic");
	const headBytes = file.subarray(0, 512);
	const zero = headBytes.indexOf(0);
	const parts = new TextDecoder("latin1").decode(zero >= 0 ? headBytes.subarray(0, zero) : headBytes).trim().split(":");
	if (parts[0] !== "ClamAV-VDB" || parts.length < 9) throw new CvdError("bad-magic");
	const body = file.subarray(512);
	const header = {
		built: parts[1],
		version: parts[2],
		reportedSignatures: Number(parts[3]),
		functionalityLevel: parts[4],
		md5: parts[5].toLowerCase(),
		builder: parts[7],
		buildTime: Number(parts[8])
	};
	if (md5Hex(body) !== header.md5) throw new CvdError("bad-md5");
	if (!verifyClamAvDsig(header.md5, parts[6])) throw new CvdError("bad-signature");
	return {
		header,
		body
	};
}
function toArrayBuffer(bytes) {
	const copy = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(copy).set(bytes);
	return copy;
}
async function gunzip(bytes) {
	const stream = new Blob([toArrayBuffer(bytes)]).stream().pipeThrough(new DecompressionStream("gzip"));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}
function extractHashRecords(tar) {
	const records = [];
	let offset = 0;
	while (offset + 512 <= tar.length) {
		const header = tar.subarray(offset, offset + 512);
		if (header.every((b) => b === 0)) break;
		const name = readString(header, 0, 100);
		const size = parseInt(readString(header, 124, 12).trim(), 8);
		const typeflag = header[156];
		const prefix = readString(header, 345, 155);
		const full = prefix ? `${prefix}/${name}` : name;
		offset += 512;
		if (!Number.isFinite(size) || size < 0 || offset + size > tar.length) throw new CvdError("bad-archive");
		const data = tar.subarray(offset, offset + size);
		const blocks = Math.ceil(size / 512);
		offset += blocks * 512;
		const base = full.split("/").pop() ?? full;
		if (typeflag !== 0 && typeflag !== 48) continue;
		if (!base.endsWith(".hdb") && !base.endsWith(".hsb")) continue;
		const text = new TextDecoder("utf-8").decode(data);
		for (const line of text.split("\n")) {
			const trimmed = line.trim();
			if (!trimmed || trimmed.startsWith("#")) continue;
			const bits = trimmed.split(":");
			if (bits.length < 3) continue;
			const hash = bits[0].toLowerCase();
			const sizeField = bits[1];
			const malname = bits[2];
			const kind = hash.length === 32 ? "md5" : hash.length === 40 ? "sha1" : hash.length === 64 ? "sha256" : null;
			if (!kind || !/^[0-9a-f]+$/.test(hash)) continue;
			const fileSize = /^\d+$/.test(sizeField) ? Number(sizeField) : null;
			records.push({
				kind,
				hash,
				size: fileSize,
				name: malname
			});
		}
	}
	return records;
}
function readString(bytes, start, length) {
	let end = start;
	const stop = start + length;
	while (end < stop && bytes[end] !== 0) end++;
	return new TextDecoder("latin1").decode(bytes.subarray(start, end));
}
async function parseCvd(file) {
	const { header, body } = parseCvdHeader(file);
	let tar;
	try {
		tar = await gunzip(body);
	} catch {
		throw new CvdError("bad-archive");
	}
	return {
		header,
		records: extractHashRecords(tar)
	};
}
/** Official EICAR standard anti-malware test file. 68 bytes, not a virus. */
var EICAR_TEXT = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
function eicarBytes() {
	return new TextEncoder().encode(EICAR_TEXT);
}
var CALL = /اتصل|كلمني|كلّمني|واتساب|واتس|whatsapp|wa\.me|call me|call now|تواصل/i;
var LURE = /رمز|otp|كلمة السر|كلمة المرور|password|cvv|حسابك|موقوف|تجميد|بطاقة|تحقق من/i;
var BRAND = /بنك|bank|paypal|ooredoo|أوريدو|اوريدو|omantel|عمانتل|واتساب|whatsapp|نماء|nama/i;
/** Pulls phone-like tokens. Six-digit codes and dotted addresses are ignored. */
function extractPhones(text) {
	const matches = text.match(/(?:\+|00)?\d[\d\s()-]{5,18}\d/g) ?? [];
	const out = [];
	for (const raw of matches) {
		const e164 = normalizePhone(raw);
		if (!e164 || out.includes(e164)) continue;
		out.push(e164);
	}
	return out;
}
function normalizePhone(raw) {
	if (raw.includes(".") || raw.includes("/")) return null;
	let compact = raw.replace(/[^\d+]/g, "");
	if (compact.startsWith("00")) compact = `+${compact.slice(2)}`;
	if (compact.startsWith("+")) {
		const digits = compact.slice(1);
		if (digits.length < 8 || digits.length > 15) return null;
		return `+${digits}`;
	}
	if (/^[79]\d{7}$/.test(compact)) return `+968${compact}`;
	if (/^968[79]\d{7}$/.test(compact)) return `+${compact}`;
	if (compact.length >= 8 && compact.length <= 15) return `+${compact}`;
	return null;
}
function analyzePhones(text, official = []) {
	const known = new Set(official.map((value) => normalizePhone(value)).filter((value) => Boolean(value)));
	const asks = CALL.test(text) && (LURE.test(text) || BRAND.test(text));
	return extractPhones(text).map((e164) => {
		if (known.has(e164)) return {
			raw: e164,
			e164,
			verdict: "clean",
			reasons: []
		};
		const reasons = [];
		if (isPremium(e164)) reasons.push("premium-rate");
		else if (asks && e164.startsWith("+") && e164.length >= 11) reasons.push("callback-lure");
		return {
			raw: e164,
			e164,
			verdict: reasons.length ? "suspicious" : "clean",
			reasons
		};
	});
}
function isPremium(e164) {
	return e164.startsWith("+882") || e164.startsWith("+883") || e164.startsWith("+979");
}
var GROUPS = [
	{
		id: "closure",
		weight: 50,
		pattern: /اغلاق|إغلاق|ايقاف|إيقاف|موقوف|تجميد|suspend|closed|closure|terminat|disabled|will be stopped/i
	},
	{
		id: "account",
		weight: 20,
		pattern: /حساب|account|الرصيد|balance/i
	},
	{
		id: "brand",
		weight: 20,
		pattern: /بنك|bank|paypal|ooredoo|أوريدو|اوريدو|omantel|عمانتل|واتساب|whatsapp|نماء|nama|apple|microsoft|instagram/i
	},
	{
		id: "callback",
		weight: 30,
		pattern: /عاود الاتصال|اعد الاتصال|أعد الاتصال|يرجى الاتصال|الرجاء الاتصال|اتصل بنا|call back|call us|ring us|dial/i
	},
	{
		id: "urgency",
		weight: 20,
		pattern: /فورا|فورًا|فوراً|خلال ساعة|مهلة|آخر تنبيه|اخر تنبيه|immediately|urgent|right away|within \d+ hour/i
	},
	{
		id: "threat",
		weight: 35,
		pattern: /غرامة|بلاغ|قانوني|شرطة|legal action|police|penalty|fine/i
	},
	{
		id: "credential",
		weight: 30,
		pattern: /كلمة المرور|كلمة السر|الرمز السري|password|one[- ]time|cvv|pin code/i
	}
];
var THRESHOLD = 70;
function scoreLure(text) {
	let best = null;
	for (const clause of clauses(text)) {
		let score = 0;
		let groups = 0;
		for (const group of GROUPS) {
			if (!group.pattern.test(clause)) continue;
			score += group.weight;
			groups += 1;
		}
		if (groups < 2) continue;
		if (!best || score > best.score) best = {
			score,
			groups,
			clause
		};
	}
	if (!best || best.score < THRESHOLD) return null;
	const clause = best.clause.replace(/\s+/g, " ").trim().slice(0, 180);
	return clause ? { clause } : null;
}
function clauses(text) {
	const parts = text.split(/[\n.!?؟]+/).map((part) => part.trim()).filter((part) => part.length >= 8);
	return parts.length ? parts : [text.trim()];
}
var SHORTENERS = /* @__PURE__ */ new Set([
	"bit.ly",
	"tinyurl.com",
	"t.co",
	"goo.gl",
	"ow.ly",
	"is.gd",
	"cutt.ly",
	"rb.gy",
	"shorturl.at",
	"tiny.cc",
	"buff.ly",
	"rebrand.ly"
]);
/** Official domains checked by the owner against the public sites. */
var DEFAULT_TRUSTED_SENDERS = [
	{
		id: "nama",
		names: [
			"نماء",
			"nama",
			"nama supply"
		],
		domains: ["nama.om", "nws.nama.om"]
	},
	{
		id: "ooredoo",
		names: ["أوريدو", "ooredoo"],
		domains: ["ooredoo.om", "ooredoo.com"]
	},
	{
		id: "omantel",
		names: ["عمانتل", "omantel"],
		domains: ["omantel.om", "omantel.com"]
	},
	{
		id: "eyewa",
		names: ["eyewa", "آيوا"],
		domains: ["eyewa.com"]
	},
	{
		id: "bankmuscat",
		names: [
			"بنك مسقط",
			"bank muscat",
			"bankmuscat"
		],
		domains: ["bankmuscat.com"]
	},
	{
		id: "bankdhofar",
		names: [
			"بنك ظفار",
			"bank dhofar",
			"bankdhofar"
		],
		domains: ["bankdhofar.com"]
	},
	{
		id: "ahlibank",
		names: [
			"البنك الأهلي",
			"ahli bank",
			"ahlibank"
		],
		domains: ["ahlibank.om"]
	},
	{
		id: "banknizwa",
		names: [
			"بنك نزوى",
			"bank nizwa",
			"banknizwa"
		],
		domains: ["banknizwa.om"]
	},
	{
		id: "nbo",
		names: [
			"بنك عمان الوطني",
			"national bank of oman",
			"nbo"
		],
		domains: ["nbo.om"]
	}
];
var BRANDS = [
	"nama.om",
	"ooredoo.om",
	"omantel.om",
	"eyewa.com",
	"google.com",
	"microsoft.com",
	"apple.com",
	"paypal.com",
	"bankmuscat.com",
	"bankdhofar.com",
	"ahlibank.om",
	"banknizwa.om",
	"soharinternational.com",
	"instagram.com",
	"whatsapp.com",
	"facebook.com"
];
var HOMO = {
	"0": "o",
	"1": "l",
	"3": "e",
	"4": "a",
	"5": "s",
	"7": "t",
	"@": "a",
	$: "s"
};
function normalizeUrl(raw) {
	let s = raw.trim();
	if (!s || s.startsWith("#")) return null;
	if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `http://${s}`;
	let url;
	try {
		url = new URL(s);
	} catch {
		return null;
	}
	if (url.protocol !== "http:" && url.protocol !== "https:") return null;
	const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
	if (!hostname) return null;
	const port = url.port;
	const host = url.protocol === "http:" && port === "80" || url.protocol === "https:" && port === "443" || port === "" ? hostname : `${hostname}:${port}`;
	let path = url.pathname || "/";
	if (path !== "/" && path.endsWith("/")) path = path.slice(0, -1);
	return {
		href: `${url.protocol}//${host}${path}${url.search}`,
		host,
		hostname
	};
}
function hostInSet(hostname, hosts) {
	let cursor = hostname.toLowerCase();
	while (cursor) {
		if (hosts.has(cursor)) return true;
		const dot = cursor.indexOf(".");
		if (dot < 0) break;
		cursor = cursor.slice(dot + 1);
		if (!cursor.includes(".")) break;
	}
	return false;
}
function analyzeUrl(raw, db) {
	const norm = normalizeUrl(raw);
	if (!norm) return null;
	const reasons = [];
	let verdict = "clean";
	if (db.urls.has(norm.href) || hostInSet(norm.hostname, db.hosts)) {
		verdict = "malicious";
		reasons.push("listed");
	}
	if (hidesDestination(raw)) {
		reasons.push("userinfo");
		if (verdict !== "malicious") verdict = "suspicious";
	}
	const lookalike = brandLookalike(norm.hostname);
	if (lookalike) {
		reasons.push("lookalike");
		if (verdict !== "malicious") verdict = "suspicious";
	}
	if (isPublicIp(norm.hostname)) {
		reasons.push("ip-host");
		if (verdict !== "malicious") verdict = "suspicious";
	}
	const embedded = embeddedBrand(norm.hostname);
	if (embedded) {
		reasons.push("brand-host");
		if (verdict !== "malicious") verdict = "suspicious";
	}
	if (verdict !== "clean" && SHORTENERS.has(norm.hostname)) reasons.push("shortener");
	if (verdict !== "clean" && norm.hostname.startsWith("xn--")) reasons.push("punycode");
	return {
		verdict,
		reasons,
		normalized: norm.href,
		host: norm.hostname,
		hint: lookalike || embedded || void 0
	};
}
function extractUrls(text) {
	const found = text.match(/((https?:\/\/|www\.)[^\s<>"']+|((?:[a-z0-9-]+\.)+[a-z]{2,})(?:\/[^\s<>"']*)?)/gi) ?? [];
	return [...new Set(found.map((item) => item.replace(/[),.;]+$/, "")))];
}
function analyzeMessage(input) {
	const urls = extractUrls(input.text).map((u) => analyzeUrl(u, input.db)).filter((u) => u !== null);
	const sender = fold(input.sender);
	const trust = input.trusted.find((row) => row.names.some((name) => fold(name) === sender));
	const reasons = /* @__PURE__ */ new Set();
	let verdict = "clean";
	for (const url of urls) {
		if (url.verdict === "malicious") verdict = "malicious";
		else if (url.verdict === "suspicious" && verdict === "clean") verdict = "suspicious";
		url.reasons.forEach((r) => reasons.add(r));
	}
	if (trust) {
		if (urls.filter((u) => !trust.domains.some((d) => u.host === d || u.host.endsWith(`.${d}`))).length > 0) {
			reasons.add("trusted-sender-off-domain");
			if (verdict === "clean") verdict = "suspicious";
		} else if (verdict !== "malicious") {
			verdict = "clean";
			reasons.clear();
		}
	}
	const phones = analyzePhones(input.text, input.official ?? []);
	for (const phone of phones) {
		if (phone.verdict === "clean") continue;
		phone.reasons.forEach((reason) => reasons.add(reason));
		if (verdict === "clean") verdict = "suspicious";
	}
	const lure = scoreLure(input.text);
	if (lure && verdict !== "malicious") {
		reasons.add("lure-model");
		verdict = "suspicious";
	}
	if (trust && verdict !== "malicious") {
		if (urls.filter((u) => !trust.domains.some((d) => u.host === d || u.host.endsWith(`.${d}`))).length === 0 && urls.length > 0) {
			verdict = "clean";
			reasons.clear();
		}
	}
	return {
		verdict,
		reasons: [...reasons],
		urls,
		phones,
		fingerprint: "",
		clause: reasons.has("lure-model") && lure ? lure.clause : ""
	};
}
function hidesDestination(raw) {
	let s = raw.trim();
	if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `http://${s}`;
	try {
		const parsed = new URL(s);
		return Boolean(parsed.username || parsed.password);
	} catch {
		return false;
	}
}
function isPublicIp(host) {
	if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
	const parts = host.split(".").map((part) => Number(part));
	if (parts.some((part) => part > 255)) return false;
	const a = parts[0] ?? 0;
	const b = parts[1] ?? 0;
	if (a === 0 || a === 10 || a === 127) return false;
	if (a === 192 && b === 168) return false;
	if (a === 172 && b >= 16 && b <= 31) return false;
	if (a === 169 && b === 254) return false;
	if (a >= 224) return false;
	return true;
}
function fold(value) {
	return value.trim().toLowerCase().replace(/[أإآ]/g, "ا").replace(/ة/g, "ه").replace(/\s+/g, " ");
}
function squash(host) {
	return [...host.toLowerCase()].map((ch) => HOMO[ch] ?? ch).join("").replace(/[^a-z0-9.]/g, "");
}
var BRAND_TOKENS = [
	"paypal",
	"bankmuscat",
	"bankdhofar",
	"ahlibank",
	"banknizwa",
	"whatsapp",
	"ooredoo",
	"omantel",
	"instagram",
	"apple",
	"microsoft"
];
function embeddedBrand(host) {
	if (BRANDS.some((brand) => host === brand || host.endsWith(`.${brand}`))) return null;
	for (const label of host.split(".")) for (const token of BRAND_TOKENS) if (label === token || label.startsWith(`${token}-`) || label.endsWith(`-${token}`) || label.includes(`-${token}-`)) return token;
	return null;
}
var ARABIC_NAMES = [
	"بنك مسقط",
	"بنك ظفار",
	"البنك الأهلي",
	"بنك نزوى",
	"أوريدو",
	"عمانتل",
	"نماء"
];
function brandLookalike(host) {
	const decoded = decodeHost(host);
	const folded = squash(decoded);
	for (const brand of BRANDS) if (host === brand || host.endsWith(`.${brand}`) || decoded === brand || decoded.endsWith(`.${brand}`)) return null;
	for (const brand of BRANDS) {
		const token = brand.split(".")[0] || brand;
		if (folded === squash(brand) || folded.endsWith(`.${squash(brand)}`)) return brand;
		for (const label of folded.split(".")) {
			if (label.length < 5 || label === token) continue;
			const distance = levenshtein(label, token);
			const limit = token.length >= 8 ? 2 : 1;
			if (distance > 0 && distance <= limit) return brand;
		}
	}
	for (const label of decoded.split(".")) {
		const compact = fold(label).replace(/\s+/g, "");
		if (compact.length < 4) continue;
		for (const name of ARABIC_NAMES) {
			const target = fold(name).replace(/\s+/g, "");
			const distance = levenshtein(compact, target);
			if (distance === 0 || distance === 1 && target.length >= 4) return name;
		}
	}
	return null;
}
function decodeHost(host) {
	return host.split(".").map((label) => label.startsWith("xn--") ? punyDecode(label.slice(4)) : label).join(".");
}
function punyDecode(input) {
	const base = 36;
	const tMin = 1;
	const tMax = 26;
	const skew = 38;
	const damp = 700;
	const initialBias = 72;
	const initialN = 128;
	const out = [];
	for (const ch of input) if (ch.charCodeAt(0) >= 128) return input;
	let i = 0;
	const basic = input.lastIndexOf("-");
	if (basic > 0) for (let k = 0; k < basic; k++) out.push(input.charCodeAt(k));
	let n = initialN;
	let bias = initialBias;
	let index = basic > 0 ? basic + 1 : 0;
	while (index < input.length) {
		const old = i;
		let w = 1;
		for (let k = base;; k += base) {
			if (index >= input.length) return input;
			const c = input.charCodeAt(index++);
			const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
			if (digit >= base) return input;
			i += digit * w;
			const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
			if (digit < t) break;
			w *= base - t;
		}
		const len = out.length + 1;
		bias = adapt(i - old, len, old === 0, damp, skew, base, tMin, tMax);
		n += Math.floor(i / len);
		i %= len;
		out.splice(i, 0, n);
		i += 1;
	}
	return String.fromCodePoint(...out);
}
function adapt(delta, numPoints, first, damp, skew, base, tMin, tMax) {
	let value = first ? Math.floor(delta / damp) : delta >> 1;
	value += Math.floor(value / numPoints);
	const gap = base - tMin;
	let k = 0;
	while (value > Math.floor(gap * tMax / 2)) {
		value = Math.floor(value / gap);
		k += base;
	}
	return k + Math.floor((gap + 1) * value / (value + skew));
}
function levenshtein(a, b) {
	if (Math.abs(a.length - b.length) > 2) return 99;
	const prev = new Array(b.length + 1);
	for (let j = 0; j <= b.length; j++) prev[j] = j;
	for (let i = 1; i <= a.length; i++) {
		let last = prev[0];
		prev[0] = i;
		for (let j = 1; j <= b.length; j++) {
			const tmp = prev[j];
			const cost = a[i - 1] === b[j - 1] ? 0 : 1;
			prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, last + cost);
			last = tmp;
		}
	}
	return prev[b.length];
}
function classify(name, bytes) {
	const lower = name.toLowerCase();
	if (/\.(apk|xapk|apks)$/.test(lower)) return "apk";
	if (/\.(docx|xlsx|xlsm|xltm|docm|pptx|pptm)$/.test(lower)) return "office";
	if (isRar(bytes) || /\.rar$/.test(lower)) return "rar";
	if (isPdf(bytes) || /\.pdf$/.test(lower)) return "pdf";
	if (isOle(bytes) || /\.(doc|xls|ppt)$/.test(lower)) return "ole";
	if (isImage(lower, bytes)) return "image";
	if (/\.(zip|jar)$/.test(lower) || looksLikeZip(bytes)) return "zip";
	return "other";
}
function looksLikeZip(bytes) {
	return bytes.length > 4 && bytes[0] === 80 && bytes[1] === 75 && (bytes[2] === 3 || bytes[2] === 5 || bytes[2] === 7);
}
function isRar(bytes) {
	return bytes.length > 6 && bytes[0] === 82 && bytes[1] === 97 && bytes[2] === 114 && bytes[3] === 33;
}
function isPdf(bytes) {
	return bytes.length > 4 && bytes[0] === 37 && bytes[1] === 80 && bytes[2] === 68 && bytes[3] === 70;
}
function isOle(bytes) {
	return bytes.length > 4 && bytes[0] === 208 && bytes[1] === 207 && bytes[2] === 17 && bytes[3] === 224;
}
function isImage(lower, bytes) {
	if (bytes.length > 8 && bytes[0] === 137 && bytes[1] === 80 && bytes[2] === 78 && bytes[3] === 71) return true;
	if (bytes.length > 3 && bytes[0] === 255 && bytes[1] === 216) return true;
	return /\.(png|jpe?g|gif|webp)$/.test(lower);
}
function shouldOpenOfficeEntry(name) {
	return /\.(exe|dll|apk|jar|zip|js|vbs|bat|cmd|scr|hta|lnk)$/i.test(name) || /(^|\/)vbaProject\.bin$/i.test(name);
}
function officeRisks(entries, db) {
	const risks = [];
	if (entries.some((entry) => /(^|\/)vbaProject\.bin$/i.test(entry.name))) risks.push({
		reasonId: "macro",
		detail: "vba"
	});
	for (const entry of entries) {
		if (!/\.rels$/i.test(entry.name) || entry.bytes.length > 2e5) continue;
		const text = new TextDecoder("utf-8", { fatal: false }).decode(entry.bytes);
		for (const raw of extractUrls(text)) {
			const verdict = analyzeUrl(raw, db);
			if (!verdict || verdict.verdict === "clean") continue;
			risks.push({
				reasonId: "doc-link",
				detail: verdict.host
			});
			return risks;
		}
	}
	return risks;
}
function looseRisks(name, bytes) {
	const risks = [];
	if (isImage(name.toLowerCase(), bytes) && imageTrailer(bytes)) risks.push({
		reasonId: "polyglot",
		detail: ""
	});
	const pdf = isPdf(bytes) || name.toLowerCase().endsWith(".pdf") ? pdfRisk(bytes) : null;
	if (pdf) risks.push({
		reasonId: pdf,
		detail: ""
	});
	if ((isOle(bytes) || /\.(doc|xls|ppt)$/i.test(name)) && oleMacro(bytes)) risks.push({
		reasonId: "macro",
		detail: "ole"
	});
	return risks;
}
function imageTrailer(bytes) {
	if (bytes[0] === 137 && bytes[1] === 80) {
		const marker = [
			73,
			69,
			78,
			68,
			174,
			66,
			96,
			130
		];
		let at = -1;
		for (let i = bytes.length - marker.length; i >= 8; i--) {
			let same = true;
			for (let j = 0; j < marker.length; j++) if (bytes[i + j] !== marker[j]) same = false;
			if (same) {
				at = i + marker.length;
				break;
			}
		}
		if (at < 0) return false;
		return payload(bytes.subarray(at));
	}
	if (bytes[0] === 255 && bytes[1] === 216) {
		let end = -1;
		for (let i = bytes.length - 2; i >= 2; i--) if (bytes[i] === 255 && bytes[i + 1] === 217) {
			end = i + 2;
			break;
		}
		if (end < 0) return false;
		return payload(bytes.subarray(end));
	}
	return false;
}
function payload(trailer) {
	let i = 0;
	while (i < trailer.length && trailer[i] <= 32) i++;
	const b = trailer.subarray(i);
	if (b.length < 16) return false;
	if (b[0] === 80 && b[1] === 75 && b[2] === 3 && b[3] === 4) return true;
	if (b[0] === 77 && b[1] === 90) return true;
	if (b[0] === 127 && b[1] === 69 && b[2] === 76 && b[3] === 70) return true;
	if (b[0] === 100 && b[1] === 101 && b[2] === 120 && b[3] === 10) return true;
	return false;
}
function pdfRisk(bytes) {
	const text = new TextDecoder("latin1").decode(bytes.subarray(0, Math.min(bytes.length, 15e5)));
	if (/\/Launch\b/.test(text)) return "pdf-launch";
	if (/\/OpenAction\b/.test(text) && (/\/JavaScript\b/.test(text) || /\/JS\b/.test(text))) return "pdf-active";
	return null;
}
function oleMacro(bytes) {
	return new TextDecoder("latin1").decode(bytes.subarray(0, Math.min(bytes.length, 4e6))).includes("_VBA_PROJECT");
}
var K = new Uint32Array([
	1116352408,
	1899447441,
	3049323471,
	3921009573,
	961987163,
	1508970993,
	2453635748,
	2870763221,
	3624381080,
	310598401,
	607225278,
	1426881987,
	1925078388,
	2162078206,
	2614888103,
	3248222580,
	3835390401,
	4022224774,
	264347078,
	604807628,
	770255983,
	1249150122,
	1555081692,
	1996064986,
	2554220882,
	2821834349,
	2952996808,
	3210313671,
	3336571891,
	3584528711,
	113926993,
	338241895,
	666307205,
	773529912,
	1294757372,
	1396182291,
	1695183700,
	1986661051,
	2177026350,
	2456956037,
	2730485921,
	2820302411,
	3259730800,
	3345764771,
	3516065817,
	3600352804,
	4094571909,
	275423344,
	430227734,
	506948616,
	659060556,
	883997877,
	958139571,
	1322822218,
	1537002063,
	1747873779,
	1955562222,
	2024104815,
	2227730452,
	2361852424,
	2428436474,
	2756734187,
	3204031479,
	3329325298
]);
function rotr(x, n) {
	return x >>> n | x << 32 - n;
}
/** Incremental SHA-256. Output is lowercase hex. */
var Sha256 = class {
	h = new Uint32Array([
		1779033703,
		3144134277,
		1013904242,
		2773480762,
		1359893119,
		2600822924,
		528734635,
		1541459225
	]);
	bytes = 0;
	buf = /* @__PURE__ */ new Uint8Array(64);
	len = 0;
	update(chunk) {
		this.bytes += chunk.length;
		let offset = 0;
		if (this.len > 0) {
			const take = Math.min(64 - this.len, chunk.length);
			this.buf.set(chunk.subarray(0, take), this.len);
			this.len += take;
			offset = take;
			if (this.len === 64) {
				this.block(this.buf);
				this.len = 0;
			}
		}
		while (offset + 64 <= chunk.length) {
			this.block(chunk.subarray(offset, offset + 64));
			offset += 64;
		}
		if (offset < chunk.length) {
			this.buf.set(chunk.subarray(offset), 0);
			this.len = chunk.length - offset;
		}
	}
	block(block) {
		const w = /* @__PURE__ */ new Uint32Array(64);
		for (let i = 0; i < 16; i++) {
			const j = i * 4;
			w[i] = (block[j] << 24 | block[j + 1] << 16 | block[j + 2] << 8 | block[j + 3]) >>> 0;
		}
		for (let i = 16; i < 64; i++) {
			const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ w[i - 15] >>> 3;
			const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ w[i - 2] >>> 10;
			w[i] = w[i - 16] + s0 + w[i - 7] + s1 >>> 0;
		}
		let a = this.h[0];
		let b = this.h[1];
		let c = this.h[2];
		let d = this.h[3];
		let e = this.h[4];
		let f = this.h[5];
		let g = this.h[6];
		let hh = this.h[7];
		for (let i = 0; i < 64; i++) {
			const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			const ch = e & f ^ ~e & g;
			const t1 = hh + s1 + ch + K[i] + w[i] >>> 0;
			const t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + (a & b ^ a & c ^ b & c) >>> 0;
			hh = g;
			g = f;
			f = e;
			e = d + t1 >>> 0;
			d = c;
			c = b;
			b = a;
			a = t1 + t2 >>> 0;
		}
		this.h[0] = this.h[0] + a >>> 0;
		this.h[1] = this.h[1] + b >>> 0;
		this.h[2] = this.h[2] + c >>> 0;
		this.h[3] = this.h[3] + d >>> 0;
		this.h[4] = this.h[4] + e >>> 0;
		this.h[5] = this.h[5] + f >>> 0;
		this.h[6] = this.h[6] + g >>> 0;
		this.h[7] = this.h[7] + hh >>> 0;
	}
	digest() {
		const bits = this.bytes * 8;
		const pad = new Uint8Array(this.len < 56 ? 64 - this.len : 128 - this.len);
		pad[0] = 128;
		const view = new DataView(pad.buffer);
		const hi = Math.floor(bits / 2 ** 32);
		view.setUint32(pad.length - 8, hi, false);
		view.setUint32(pad.length - 4, bits >>> 0, false);
		this.update(pad);
		const out = /* @__PURE__ */ new Uint8Array(32);
		for (let i = 0; i < 8; i++) {
			out[i * 4] = this.h[i] >>> 24 & 255;
			out[i * 4 + 1] = this.h[i] >>> 16 & 255;
			out[i * 4 + 2] = this.h[i] >>> 8 & 255;
			out[i * 4 + 3] = this.h[i] & 255;
		}
		return out;
	}
	hex() {
		return [...this.digest()].map((b) => b.toString(16).padStart(2, "0")).join("");
	}
};
function sha256Hex(data) {
	const h = new Sha256();
	h.update(data);
	return h.hex();
}
var RSA_OID = [
	42,
	134,
	72,
	134,
	247,
	13,
	1,
	1,
	1
];
var EC_OID = [
	42,
	134,
	72,
	206,
	61,
	2,
	1
];
function certificatesFromPkcs(bytes) {
	const hits = [];
	const debug = includesAscii(bytes, "Android Debug");
	for (let i = 0; i < bytes.length - 8; i++) {
		if (bytes[i] !== 48) continue;
		const parsed = readDer(bytes, i);
		if (!parsed) continue;
		const cert = parsed.bytes;
		if (cert.length < 128 || cert.length > 2e4) continue;
		if (!containsOid(cert, RSA_OID) && !containsOid(cert, EC_OID)) continue;
		hits.push({
			sha256: sha256Hex(cert),
			debug: debug || includesAscii(cert, "Android Debug")
		});
		i += cert.length - 1;
	}
	return hits;
}
function containsOid(bytes, oid) {
	outer: for (let i = 0; i + oid.length < bytes.length; i++) {
		for (let j = 0; j < oid.length; j++) if (bytes[i + j] !== oid[j]) continue outer;
		return true;
	}
	return false;
}
function readDer(bytes, offset) {
	if (offset >= bytes.length || bytes[offset] !== 48) return null;
	const len = readLen(bytes, offset + 1);
	if (!len) return null;
	const end = len.next + len.value;
	if (end > bytes.length) return null;
	return { bytes: bytes.subarray(offset, end) };
}
function readLen(bytes, offset) {
	if (offset >= bytes.length) return null;
	const first = bytes[offset];
	if ((first & 128) === 0) return {
		value: first,
		next: offset + 1
	};
	const count = first & 127;
	if (count === 0 || count > 3 || offset + 1 + count > bytes.length) return null;
	let value = 0;
	for (let i = 0; i < count; i++) value = value << 8 | bytes[offset + 1 + i];
	return {
		value,
		next: offset + 1 + count
	};
}
function includesAscii(bytes, text) {
	const needle = new TextEncoder().encode(text);
	outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
		for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
		return true;
	}
	return false;
}
/** Android binary XML string pool. Enough to read permissions and intent names. */
function axmlStrings(bytes) {
	if (bytes.length < 28) return [];
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	if (view.getUint32(0, true) !== 524291) return [];
	let offset = 8;
	if (36 > bytes.length) return [];
	if (view.getUint16(offset, true) !== 1) return [];
	const stringCount = view.getUint32(16, true);
	const flags = view.getUint32(24, true);
	const stringsStart = view.getUint32(28, true);
	const utf8 = (flags & 256) !== 0;
	if (stringCount > 1e5) return [];
	const offsets = [];
	const table = 36;
	for (let i = 0; i < stringCount; i++) {
		if (table + (i + 1) * 4 > bytes.length) break;
		offsets.push(view.getUint32(table + i * 4, true));
	}
	const pool = offset + stringsStart;
	const out = [];
	for (const rel of offsets) {
		const start = pool + rel;
		if (start < 0 || start >= bytes.length) continue;
		if (utf8) out.push(readUtf8String(bytes, start));
		else out.push(readUtf16String(bytes, start));
	}
	return out;
}
function readUtf8String(bytes, offset) {
	let p = offset;
	const skip = (at) => (bytes[at] & 128) === 0 ? 1 : 2;
	if (p >= bytes.length) return "";
	p += skip(p);
	if (p >= bytes.length) return "";
	const lenInfo = bytes[p] & 128 ? (bytes[p] & 127) << 8 | bytes[p + 1] : bytes[p];
	p += skip(p);
	const end = Math.min(bytes.length, p + lenInfo);
	return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(p, end));
}
function readUtf16String(bytes, offset) {
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	if (offset + 2 > bytes.length) return "";
	let charCount = view.getUint16(offset, true);
	let p = offset + 2;
	if (charCount & 32768) {
		if (p + 2 > bytes.length) return "";
		charCount = (charCount & 32767) << 16 | view.getUint16(p, true);
		p += 2;
	}
	const byteLen = Math.min(bytes.length - p, charCount * 2);
	return new TextDecoder("utf-16le", { fatal: false }).decode(bytes.subarray(p, p + byteLen));
}
var PACKERS = [
	"com.qihoo.util.",
	"com.secneo.apkwrapper.",
	"com.secneo.",
	"com.bangcle.",
	"com.ijiami.",
	"com.baidu.protect.",
	"com.safedex.",
	"com.tianyu."
];
function packerName(text) {
	if (text.length > 160) return null;
	const lower = text.toLowerCase();
	return PACKERS.find((name) => lower === name.slice(0, -1) || lower.startsWith(name)) ?? null;
}
function blankDex() {
	return {
		dynamicLoad: false,
		packer: null,
		shortNameRatio: 0,
		stringsSeen: 0,
		smsApi: false,
		accessApi: false,
		hideIcon: false,
		adminApi: false
	};
}
function noteDexString(flags, text) {
	if (text.length === 0 || text.length > 180) return;
	if (!flags.smsApi && (text.includes("SmsManager") || text.includes("sendTextMessage") || text.includes("sendMultipartTextMessage"))) flags.smsApi = true;
	if (!flags.accessApi && (text.includes("AccessibilityService") || text.includes("onAccessibilityEvent"))) flags.accessApi = true;
	if (!flags.hideIcon && text.includes("COMPONENT_ENABLED_STATE_DISABLED")) flags.hideIcon = true;
	if (!flags.adminApi && (text.includes("DeviceAdminReceiver") || text.includes("DEVICE_ADMIN_ENABLED"))) flags.adminApi = true;
}
function dexSignals(bytes) {
	const empty = blankDex();
	if (bytes.length < 112) return empty;
	if (new TextDecoder("latin1").decode(bytes.subarray(0, 4)) !== "dex\n") return scanRaw(bytes);
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const endian = view.getUint32(40, true);
	const little = endian === 305419896;
	if (!little && endian !== 2018915346) return scanRaw(bytes);
	const stringCount = view.getUint32(56, little);
	const stringOff = view.getUint32(60, little);
	if (stringCount > 2e5 || stringOff > bytes.length) return scanRaw(bytes);
	let dynamic = false;
	let packer = null;
	let short = 0;
	let seen = 0;
	const flags = blankDex();
	const max = Math.min(stringCount, 8e4);
	for (let i = 0; i < max; i++) {
		const idAt = stringOff + i * 4;
		if (idAt + 4 > bytes.length) break;
		const text = readUlebString(bytes, view.getUint32(idAt, little));
		if (!text) continue;
		seen++;
		if (text.length <= 2) short++;
		if (text.includes("DexClassLoader") || text.includes("InMemoryDexClassLoader") || text.includes("BaseDexClassLoader")) dynamic = true;
		noteDexString(flags, text);
		if (!packer) packer = packerName(text);
	}
	flags.dynamicLoad = dynamic;
	flags.packer = packer;
	flags.shortNameRatio = seen ? short / seen : 0;
	flags.stringsSeen = seen;
	return flags;
}
function scanRaw(bytes) {
	const text = new TextDecoder("latin1", { fatal: false }).decode(bytes.subarray(0, Math.min(bytes.length, 2e6)));
	const flags = blankDex();
	flags.dynamicLoad = text.includes("DexClassLoader");
	flags.packer = PACKERS.find((name) => text.toLowerCase().includes(name)) ?? null;
	noteDexString(flags, text.length > 180 ? text.slice(0, 180) : text);
	const window = 180;
	for (let i = 0; i < text.length && i < 2e6; i += 120) {
		noteDexString(flags, text.slice(i, i + window));
		if (flags.smsApi && flags.accessApi && flags.hideIcon && flags.adminApi) break;
	}
	return flags;
}
function readUlebString(bytes, offset) {
	if (offset < 0 || offset >= bytes.length) return "";
	let p = offset;
	let size = 0;
	let shift = 0;
	for (let k = 0; k < 5 && p < bytes.length; k++) {
		const b = bytes[p++];
		size |= (b & 127) << shift;
		if ((b & 128) === 0) break;
		shift += 7;
	}
	const end = Math.min(bytes.length, p + size * 3);
	let stop = p;
	while (stop < end && bytes[stop] !== 0) stop++;
	return new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(p, stop));
}
var HEURISTIC_WEIGHTS = {
	overlayAndAccessibility: 100,
	smsAndInternet: 100,
	deviceAdmin: 100,
	knownPacker: 100,
	testKey: 100,
	installAndInternet: 100,
	dexSmsAccess: 100,
	hideIcon: 100,
	dexAdmin: 100,
	smsAccess: 100,
	smsOverlay: 100
};
var PERM = {
	overlay: "android.permission.SYSTEM_ALERT_WINDOW",
	accessibility: "android.permission.BIND_ACCESSIBILITY_SERVICE",
	sms: "android.permission.RECEIVE_SMS",
	readSms: "android.permission.READ_SMS",
	internet: "android.permission.INTERNET",
	admin: "android.permission.BIND_DEVICE_ADMIN",
	install: "android.permission.REQUEST_INSTALL_PACKAGES"
};
function scoreApplication(input) {
	const set = new Set(input.strings);
	const permissions = [...set].filter((s) => s.startsWith("android.permission.")).sort();
	const reasons = [];
	let score = 0;
	const has = (name) => set.has(name) || permissions.includes(name);
	const launcher = input.strings.some((item) => item.includes("android.intent.category.LAUNCHER"));
	const overlay = has(PERM.overlay);
	const accessibility = has(PERM.accessibility);
	const sms = has(PERM.sms) || has(PERM.readSms);
	const internet = has(PERM.internet);
	const admin = has(PERM.admin);
	const install = has(PERM.install);
	const packer = Boolean(input.dex.packer);
	if (overlay && accessibility) {
		score += HEURISTIC_WEIGHTS.overlayAndAccessibility;
		reasons.push("overlay-accessibility");
	}
	if (sms && internet && (!launcher || overlay || admin)) {
		score += HEURISTIC_WEIGHTS.smsAndInternet;
		reasons.push("sms-internet");
	}
	if (admin && (overlay || sms || !launcher)) {
		score += HEURISTIC_WEIGHTS.deviceAdmin;
		reasons.push("device-admin");
	}
	if (packer && (overlay || sms || !launcher || input.dex.dynamicLoad)) {
		score += HEURISTIC_WEIGHTS.knownPacker;
		reasons.push("packer");
	}
	if (install && internet && !launcher && (sms || overlay || admin)) {
		score += HEURISTIC_WEIGHTS.installAndInternet;
		reasons.push("install-internet");
	}
	if (input.debugCert && (overlay || sms || packer)) {
		score += HEURISTIC_WEIGHTS.testKey;
		reasons.push("test-key");
	}
	if (input.dex.smsApi && input.dex.accessApi) {
		score += HEURISTIC_WEIGHTS.dexSmsAccess;
		reasons.push("dex-sms-access");
	}
	if (input.dex.hideIcon && (input.dex.smsApi || input.dex.accessApi || sms || accessibility)) {
		score += HEURISTIC_WEIGHTS.hideIcon;
		reasons.push("hide-icon");
	}
	if (input.dex.adminApi && (sms || overlay || accessibility || input.dex.smsApi || !launcher)) {
		score += HEURISTIC_WEIGHTS.dexAdmin;
		reasons.push("dex-admin");
	}
	if (sms && accessibility) {
		score += HEURISTIC_WEIGHTS.smsAccess;
		reasons.push("sms-access");
	}
	if (sms && overlay) {
		score += HEURISTIC_WEIGHTS.smsOverlay;
		reasons.push("sms-overlay");
	}
	return {
		score,
		reasons,
		permissions
	};
}
var STORE_PREFIXES = [
	"com.google.",
	"com.android.",
	"android.",
	"com.samsung.",
	"com.sec.",
	"com.microsoft.",
	"com.facebook.",
	"com.instagram.",
	"com.whatsapp",
	"org.telegram.",
	"com.twitter.",
	"com.spotify.",
	"com.snapchat.",
	"com.amazon.",
	"com.huawei.",
	"com.xiaomi.",
	"com.miui.",
	"com.oppo.",
	"com.coloros.",
	"com.heytap.",
	"com.oplus.",
	"com.oneplus.",
	"com.vivo.",
	"com.realme.",
	"com.sony.",
	"com.lge.",
	"com.motorola."
];
function isStorePackage(path) {
	const name = path.match(/(?:^|\/)apps\/([a-zA-Z][\w.]*)/)?.[1]?.toLowerCase();
	if (!name) return false;
	return STORE_PREFIXES.some((prefix) => name === prefix || name.startsWith(prefix));
}
var EMPTY_DEX = {
	dynamicLoad: false,
	packer: null,
	shortNameRatio: 0,
	stringsSeen: 0,
	smsApi: false,
	accessApi: false,
	hideIcon: false,
	adminApi: false
};
function scoreBehavior(input) {
	if (isStorePackage(input.path)) return {
		score: 0,
		ratio: 0,
		band: "clean",
		reasons: [],
		permissions: []
	};
	const hit = scoreApplication({
		strings: input.strings,
		dex: input.dex ?? EMPTY_DEX,
		debugCert: input.debugCert ?? false
	});
	const ratio = Math.min(1, hit.score / 100);
	return {
		...hit,
		ratio,
		band: hit.score >= 100 ? "suspicious" : "clean"
	};
}
function emptyDb() {
	return {
		hashes: /* @__PURE__ */ new Map(),
		hosts: /* @__PURE__ */ new Set(),
		urls: /* @__PURE__ */ new Set(),
		certs: /* @__PURE__ */ new Map(),
		sources: [],
		builtAt: "",
		hashRecords: 0
	};
}
function lookupHash(db, kind, hash, size) {
	const rows = db.hashes.get(`${kind}:${hash.toLowerCase()}`);
	if (!rows) return null;
	return rows.find((row) => row.size === null || row.size === size) ?? null;
}
function parseHashTsv(text, db) {
	let n = 0;
	for (const line of text.split("\n")) {
		if (!line) continue;
		const [kind, hash, size, source, ...nameParts] = line.split("	");
		if (kind !== "md5" && kind !== "sha1" && kind !== "sha256") continue;
		if (!hash) continue;
		const key = `${kind}:${hash}`;
		const hit = {
			size: size === "*" || !/^\d+$/.test(size) ? null : Number(size),
			source: source ?? "",
			name: nameParts.join("	")
		};
		const list = db.hashes.get(key);
		if (list) {
			if (!list.some((row) => row.name === hit.name && row.source === hit.source)) list.push(hit);
		} else {
			db.hashes.set(key, [hit]);
			n++;
		}
	}
	db.hashRecords += n;
	return n;
}
function parseHosts(text, db) {
	let n = 0;
	for (const line of text.split("\n")) {
		const host = line.trim().toLowerCase();
		if (!host || host.startsWith("#")) continue;
		db.hosts.add(host);
		n++;
	}
	return n;
}
function parseUrls(text, db) {
	let n = 0;
	for (const line of text.split("\n")) {
		const url = line.trim();
		if (!url || url.startsWith("#")) continue;
		db.urls.add(url);
		n++;
	}
	return n;
}
function parseCerts(text, db) {
	let n = 0;
	for (const line of text.split("\n")) {
		if (!line) continue;
		const [thumb, ...reason] = line.split("	");
		if (!/^[0-9a-f]{64}$/.test(thumb)) continue;
		db.certs.set(thumb, reason.join("	") || "CSCB");
		n++;
	}
	return n;
}
var DEFAULT_ZIP_LIMITS = {
	maxEntries: 2e3,
	maxUncompressed: 67108864,
	maxRatio: 100,
	ratioFloor: 4194304,
	maxSingle: 33554432
};
var ZipLimitError = class extends Error {
	code;
	constructor(code) {
		super(code);
		this.name = "ZipLimitError";
		this.code = code;
	}
};
var SIG_EOCD = 101010256;
var SIG_CENTRAL = 33639248;
function u16(view, offset) {
	return view.getUint16(offset, true);
}
function u32(view, offset) {
	return view.getUint32(offset, true);
}
async function readZip(data, limits = DEFAULT_ZIP_LIMITS, pick) {
	const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
	let eocd = -1;
	const start = Math.max(0, data.length - 22 - 65535);
	for (let i = data.length - 22; i >= start; i--) if (u32(view, i) === SIG_EOCD) {
		eocd = i;
		break;
	}
	if (eocd < 0) throw new ZipLimitError("corrupt");
	const count = u16(view, eocd + 10);
	const centralSize = u32(view, eocd + 12);
	const centralOffset = u32(view, eocd + 16);
	if (count > (pick ? 5e4 : limits.maxEntries)) throw new ZipLimitError(pick ? "corrupt" : "entries");
	if (centralOffset + centralSize > data.length) throw new ZipLimitError("corrupt");
	const entries = [];
	let total = 0;
	let cursor = centralOffset;
	for (let n = 0; n < count; n++) {
		if (cursor + 46 > data.length || u32(view, cursor) !== SIG_CENTRAL) throw new ZipLimitError("corrupt");
		const flags = u16(view, cursor + 8);
		const method = u16(view, cursor + 10);
		const compSize = u32(view, cursor + 20);
		const uncompSize = u32(view, cursor + 24);
		const nameLen = u16(view, cursor + 28);
		const extraLen = u16(view, cursor + 30);
		const commentLen = u16(view, cursor + 32);
		const localOffset = u32(view, cursor + 42);
		const name = new TextDecoder("utf-8", { fatal: false }).decode(data.subarray(cursor + 46, cursor + 46 + nameLen));
		cursor += 46 + nameLen + extraLen + commentLen;
		if (name.endsWith("/")) continue;
		if (pick && !pick(name)) continue;
		if (uncompSize === 4294967295 || compSize === 4294967295) {
			if (pick) continue;
			throw new ZipLimitError("size");
		}
		if (uncompSize > limits.maxSingle) {
			if (pick) continue;
			throw new ZipLimitError("size");
		}
		total += uncompSize;
		if (total > limits.maxUncompressed) {
			total -= uncompSize;
			if (pick) continue;
			throw new ZipLimitError("size");
		}
		const ratio = uncompSize / Math.max(1, compSize);
		if (uncompSize >= limits.ratioFloor && ratio > limits.maxRatio) {
			if (pick) continue;
			throw new ZipLimitError("ratio");
		}
		if (flags & 1) continue;
		if (localOffset + 30 > data.length) throw new ZipLimitError("corrupt");
		const localName = u16(view, localOffset + 26);
		const localExtra = u16(view, localOffset + 28);
		const dataStart = localOffset + 30 + localName + localExtra;
		const compressed = data.subarray(dataStart, dataStart + compSize);
		if (dataStart + compSize > data.length) throw new ZipLimitError("corrupt");
		let bytes;
		if (method === 0) bytes = compressed;
		else if (method === 8) bytes = await inflateRaw(compressed);
		else continue;
		if (bytes.length !== uncompSize && uncompSize !== 0) {
			if (bytes.length > limits.maxSingle) throw new ZipLimitError("size");
		}
		entries.push({
			name,
			method,
			compressedSize: compSize,
			uncompressedSize: bytes.length,
			bytes
		});
	}
	return entries;
}
async function inflateRaw(data) {
	const copy = new ArrayBuffer(data.byteLength);
	new Uint8Array(copy).set(data);
	const stream = new Blob([copy]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}
function isArchiveName(name) {
	return /\.(zip|apk|xapk|apks|jar|docx|xlsx|xlsm|xltm|docm|pptx|pptm)$/i.test(name);
}
function apkPart(name) {
	return /(^|\/)AndroidManifest\.xml$/i.test(name) || /(^|\/)classes\d*\.dex$/i.test(name) || /^META-INF\/.+\.(RSA|DSA|EC)$/i.test(name);
}
var DEEP_LIMITS = {
	...DEFAULT_ZIP_LIMITS,
	maxDepth: 3
};
var QUICK_LIMITS = {
	...DEFAULT_ZIP_LIMITS,
	maxDepth: 1,
	maxUncompressed: 33554432,
	maxSingle: 16777216
};
async function hashBuffer(bytes) {
	const md5 = new Md5();
	const sha = new Sha256();
	const step = 65536;
	for (let i = 0; i < bytes.length; i += step) {
		const slice = bytes.subarray(i, i + step);
		md5.update(slice);
		sha.update(slice);
	}
	return {
		md5: md5.hex(),
		sha256: sha.hex()
	};
}
async function inspectBytes(input) {
	const limits = input.limits ?? DEEP_LIMITS;
	const depth = input.depth ?? 0;
	const { md5, sha256 } = await hashBuffer(input.bytes);
	if (input.allow.has(sha256) || input.allow.has(md5)) return [];
	const found = [];
	const hashHit = lookupHash(input.db, "sha256", sha256, input.bytes.length) ?? lookupHash(input.db, "md5", md5, input.bytes.length);
	if (hashHit) {
		const eicar = /eicar/i.test(hashHit.name);
		found.push({
			name: input.name,
			path: input.path,
			size: input.bytes.length,
			md5,
			sha256,
			verdict: "malicious",
			reasonId: eicar ? "eicar" : "hash-match",
			detail: hashHit.name,
			permissions: [],
			signatureName: hashHit.name,
			sourceId: hashHit.source
		});
	}
	if (input.markers?.length) {
		const judged = scoreBehavior({
			path: input.path,
			strings: input.markers
		});
		if (judged.band === "suspicious" && !found.some((item) => item.verdict === "malicious" && item.path === input.path)) found.push({
			...base(input, md5, sha256, "suspicious", "heuristic", judged.reasons.join(",")),
			permissions: judged.permissions
		});
	}
	if (isArchiveName(input.name) || looksLikeZip(input.bytes) && !isRar(input.bytes) && classify(input.name, input.bytes) !== "image") {
		if (depth >= limits.maxDepth) {
			found.push(base(input, md5, sha256, "suspicious", "archive-depth", String(limits.maxDepth)));
			return dedupe(found);
		}
		const apk = /\.(apk|xapk|apks)$/i.test(input.name);
		const office = /\.(docx|xlsx|xlsm|xltm|docm|pptx|pptm)$/i.test(input.name);
		try {
			const entries = await readZip(input.bytes, apk ? {
				...limits,
				maxEntries: 5e4,
				maxSingle: 83886080,
				maxUncompressed: 251658240
			} : limits, apk ? (name) => apkPart(name) || /\.(zip|jar)$/i.test(name) : void 0);
			const manifest = entries.find((e) => e.name === "AndroidManifest.xml" || e.name.endsWith("/AndroidManifest.xml"));
			const dex = entries.filter((e) => /(^|\/)classes\d*\.dex$/i.test(e.name));
			const certBlobs = entries.filter((e) => /^META-INF\/.+\.(RSA|DSA|EC)$/i.test(e.name));
			if (manifest || dex.length || apk) {
				const strings = [...manifest ? axmlStrings(manifest.bytes) : [], ...input.markers ?? []];
				const dexInfo = dex.reduce((acc, entry) => {
					const next = dexSignals(entry.bytes);
					return {
						dynamicLoad: acc.dynamicLoad || next.dynamicLoad,
						packer: acc.packer ?? next.packer,
						shortNameRatio: Math.max(acc.shortNameRatio, next.shortNameRatio),
						stringsSeen: acc.stringsSeen + next.stringsSeen,
						smsApi: acc.smsApi || next.smsApi,
						accessApi: acc.accessApi || next.accessApi,
						hideIcon: acc.hideIcon || next.hideIcon,
						adminApi: acc.adminApi || next.adminApi
					};
				}, {
					dynamicLoad: false,
					packer: null,
					shortNameRatio: 0,
					stringsSeen: 0,
					smsApi: false,
					accessApi: false,
					hideIcon: false,
					adminApi: false
				});
				let debug = false;
				for (const cert of certBlobs) for (const hit of certificatesFromPkcs(cert.bytes)) {
					debug = debug || hit.debug;
					const listed = input.db.certs.get(hit.sha256);
					if (listed) found.push({
						...base(input, md5, sha256, "malicious", "bad-cert", listed),
						signatureName: listed,
						sourceId: "cscb"
					});
				}
				const judged = scoreBehavior({
					path: input.path,
					strings,
					dex: dexInfo,
					debugCert: debug
				});
				if (judged.band === "suspicious" && !isStorePackage(input.path) && !found.some((item) => item.verdict === "malicious" && item.path === input.path)) found.push({
					...base(input, md5, sha256, "suspicious", "heuristic", judged.reasons.join(",")),
					permissions: judged.permissions
				});
			}
			if (office) for (const risk of officeRisks(entries, input.db)) found.push(base(input, md5, sha256, "suspicious", risk.reasonId, risk.detail));
			for (const entry of entries) {
				if (apk && !isArchiveName(entry.name)) continue;
				if (office && !shouldOpenOfficeEntry(entry.name)) continue;
				if (entry.uncompressedSize > 8388608 && apk) continue;
				const inner = await inspectBytes({
					name: entry.name.split("/").pop() || entry.name,
					path: `${input.path}/${entry.name}`,
					bytes: entry.bytes,
					db: input.db,
					allow: input.allow,
					limits,
					depth: depth + 1
				});
				found.push(...inner.filter((item) => item.verdict === "malicious" || !apk));
			}
		} catch {}
	}
	if (!found.some((item) => item.verdict === "malicious")) for (const risk of looseRisks(input.name, input.bytes)) found.push(base(input, md5, sha256, "suspicious", risk.reasonId, risk.detail));
	return dedupe(found);
}
function base(input, md5, sha256, verdict, reasonId, detail) {
	return {
		name: input.name,
		path: input.path,
		size: input.bytes.length,
		md5,
		sha256,
		verdict,
		reasonId,
		detail,
		permissions: []
	};
}
function dedupe(items) {
	const seen = /* @__PURE__ */ new Set();
	const out = [];
	for (const item of items) {
		const key = `${item.path}|${item.reasonId}|${item.sha256}`;
		if (seen.has(key)) continue;
		seen.add(key);
		out.push(item);
	}
	return out;
}
function urlsToFeed(raw) {
	if (/<html/i.test(raw.slice(0, 200))) throw new Error("not a url feed");
	const lines = [];
	for (const line of raw.split("\n")) {
		const norm = normalizeUrl(line.trim());
		if (norm) lines.push(`U ${norm.href}`);
	}
	return lines.join("\n");
}
function ipsToFeed(raw) {
	const lines = [];
	for (const line of raw.split("\n")) {
		const ip = line.trim();
		if (!ip || ip.startsWith("#")) continue;
		if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) lines.push(`H ${ip}`);
	}
	return lines.join("\n");
}
/** ThreatFox recent CSV. Confidence below 75 is ignored so a weak report is not a hit. */
function threatFoxToFeed(raw) {
	const lines = [];
	for (const line of raw.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed.startsWith("\"")) continue;
		const cols = trimmed.replace(/^"|"$/g, "").split(/"\s*,\s*"/).map((col) => col.trim());
		if (cols.length < 10) continue;
		const value = cols[2] ?? "";
		const type = cols[3] ?? "";
		const confidence = Number(cols[9]);
		if (!Number.isFinite(confidence) || confidence < 75) continue;
		const name = (cols[7] || cols[5] || "ThreatFox").replaceAll("	", " ").slice(0, 80);
		if (type === "url") {
			const norm = normalizeUrl(value);
			if (norm) lines.push(`U ${norm.href}`);
		} else if (type === "domain" && value.includes(".")) lines.push(`H ${value.toLowerCase()}`);
		else if (type === "ip:port") {
			const ip = value.split(":")[0] ?? "";
			if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) lines.push(`H ${ip}`);
		} else if (type === "sha256_hash" && /^[0-9a-f]{64}$/i.test(value)) lines.push(`sha256\t${value.toLowerCase()}\t*\tthreatfox\t${name}`);
		else if (type === "md5_hash" && /^[0-9a-f]{32}$/i.test(value)) lines.push(`md5\t${value.toLowerCase()}\t*\tthreatfox\t${name}`);
	}
	return lines.join("\n");
}
var DEFAULT_SETTINGS = {
	wifiOnly: true,
	cloudFeeds: false,
	lastFeeds: 0,
	scheduleEnabled: false,
	every: "day",
	chargingOnly: false,
	lastScheduled: 0,
	officialNumbers: [],
	blockedNumbers: [],
	cloudKey: ""
};
var idleScan = {
	running: false,
	phase: "idle",
	mode: null,
	done: 0,
	total: 0,
	current: "",
	found: 0,
	message: ""
};
var useKanaf = create(() => ({
	booted: false,
	dbStatus: "loading",
	dbProgress: 0,
	hashCount: 0,
	sources: [],
	findings: [],
	vault: [],
	allow: [],
	folders: [],
	log: [],
	trusted: DEFAULT_TRUSTED_SENDERS.map((row) => ({
		id: row.id,
		names: [...row.names],
		domains: [...row.domains]
	})),
	settings: DEFAULT_SETTINGS,
	scan: idleScan,
	realtime: false,
	realtimeNote: "",
	lastClean: false,
	lastScan: null,
	checked: [],
	notice: "",
	shell: "web",
	integrity: "",
	device: null
}));
var database = emptyDb();
var blobs = /* @__PURE__ */ new Map();
var folderHandles = /* @__PURE__ */ new Map();
var scanAbort = false;
function getDatabase() {
	return database;
}
function setDatabase(db) {
	database = db;
}
function rememberBlob(id, bytes) {
	if (bytes.byteLength <= 33554432) blobs.set(id, bytes);
}
function takeBlob(id) {
	return blobs.get(id);
}
function dropBlob(id) {
	blobs.delete(id);
}
function rememberFolder(id, handle) {
	folderHandles.set(id, handle);
}
function folderHandle(id) {
	return folderHandles.get(id);
}
function requestCancel() {
	scanAbort = true;
}
function resetCancel() {
	scanAbort = false;
}
function cancelled() {
	return scanAbort;
}
function patch(partial) {
	useKanaf.setState(partial);
}
async function vaultKey() {
	const existing = (await import("./idb-CP9J3lcI.mjs").then((n) => n.a).then((n) => n.i).then((m) => m.idbAll("meta"))).find((row) => row.id === "vault-key" && row.key);
	if (existing?.key) return existing.key;
	const key = await crypto.subtle.generateKey({
		name: "AES-GCM",
		length: 256
	}, false, ["encrypt", "decrypt"]);
	await idbPut("meta", {
		id: "vault-key",
		key
	});
	return key;
}
async function seal(bytes, meta) {
	const key = await vaultKey();
	const iv = crypto.getRandomValues(/* @__PURE__ */ new Uint8Array(12));
	const copy = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
	const cipher = await crypto.subtle.encrypt({
		name: "AES-GCM",
		iv
	}, key, copy);
	const record = {
		...meta,
		iv: iv.buffer,
		data: cipher
	};
	await idbPut("quarantine", record);
	return record;
}
async function openVault(record) {
	const key = await vaultKey();
	const plain = await crypto.subtle.decrypt({
		name: "AES-GCM",
		iv: new Uint8Array(record.iv)
	}, key, record.data);
	return new Uint8Array(plain);
}
async function destroyVault(id) {
	await idbDelete("quarantine", id);
}
function kanafNative() {
	if (typeof window === "undefined") return null;
	const native = window.KanafNative;
	if (!native || typeof native.pick !== "function") return null;
	return native;
}
var nativeWait = null;
var netWait = null;
var netStatus = "";
var permWait = null;
if (typeof window !== "undefined") {
	const cryptoObj = globalThis.crypto;
	if (cryptoObj && typeof cryptoObj.randomUUID !== "function") {
		const fallback = () => {
			const bytes = /* @__PURE__ */ new Uint8Array(16);
			if (typeof cryptoObj.getRandomValues === "function") cryptoObj.getRandomValues(bytes);
			else for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
			bytes[6] = bytes[6] & 15 | 64;
			bytes[8] = bytes[8] & 63 | 128;
			const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
			return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
		};
		try {
			Object.defineProperty(cryptoObj, "randomUUID", { value: fallback });
		} catch {
			cryptoObj.randomUUID = fallback;
		}
	}
	window.__kanafDeliver = (payload) => {
		const wait = nativeWait;
		nativeWait = null;
		if (!wait) return;
		if (!payload) {
			wait(null);
			return;
		}
		try {
			const parsed = JSON.parse(payload);
			wait(Array.isArray(parsed.files) ? parsed.files : []);
		} catch {
			wait(null);
		}
	};
	window.__kanafNet = (id, ok, status) => {
		netStatus = status || "";
		netWait?.(id, ok);
	};
	window.__kanafPerm = (ok) => {
		const wait = permWait;
		permWait = null;
		wait?.(ok);
	};
	window.__kanafLive = (id, name) => {
		const url = `https://appassets.androidplatform.net/__apk/${encodeURIComponent(id)}`;
		scanFiles("live", [{
			name: name || id,
			path: name || id,
			url
		}]);
	};
	window.__kanafNotice = (text) => {
		reviewNotice(String(text || ""));
	};
	window.__kanafHash = (name, sha, size) => {
		reviewHash(String(name || ""), String(sha || ""), Number(size) || 0);
	};
}
var waitingHashes = [];
var waitingNotice = "";
async function reviewHash(name, sha, size) {
	if (!/^[a-f0-9]{64}$/.test(sha)) return;
	if (useKanaf.getState().dbStatus !== "ready") {
		waitingHashes.push({
			name,
			sha,
			size
		});
		return;
	}
	const hit = lookupHash(getDatabase(), "sha256", sha, size);
	if (!hit) return;
	kanafNative()?.note?.(name);
	if (useKanaf.getState().findings.some((item) => item.sha256 === sha)) return;
	await addFindings([{
		kind: "file",
		name: name || sha.slice(0, 12),
		path: name || sha,
		size,
		sha256: sha,
		md5: "",
		verdict: "malicious",
		reasonId: /eicar/i.test(hit.name) ? "eicar" : "hash-match",
		detail: hit.name,
		permissions: []
	}], [{ idHint: sha }]);
}
async function reviewNotice(text) {
	const sample = text.slice(0, 4e3);
	if (!sample.trim()) return;
	if (useKanaf.getState().dbStatus !== "ready") {
		waitingNotice = sample;
		return;
	}
	const result = inspectMessage("notification", sample);
	for (const url of result.urls) {
		if (url.verdict === "clean") continue;
		await keepMessageFinding("notification", sha256Hex(new TextEncoder().encode(url.normalized)), url.reasons[0] || "listed", url.host, url.verdict);
	}
}
async function drainNative() {
	const native = kanafNative();
	const notice = waitingNotice || native?.pendingNotice?.() || "";
	waitingNotice = "";
	let rows = [];
	try {
		rows = JSON.parse(native?.pendingHashes?.() || "[]");
	} catch {
		rows = [];
	}
	let certs = [];
	try {
		certs = JSON.parse(native?.pendingCerts?.() || "[]");
	} catch {
		certs = [];
	}
	native?.clearPending?.();
	for (const row of waitingHashes.splice(0)) rows.push(row);
	if (notice) await reviewNotice(notice);
	for (const row of rows) {
		if (!row.sha) continue;
		await reviewHash(row.name || "", row.sha, Number(row.size) || 0);
	}
	for (const row of certs) {
		if (!row.pkg || !row.before || !row.after || row.before === row.after) continue;
		const after = row.after;
		if (useKanaf.getState().findings.some((item) => item.reasonId === "cert-changed" && item.path === `apps/${row.pkg}` && item.detail.endsWith(after.slice(0, 12)))) continue;
		await addFindings([{
			kind: "file",
			name: row.pkg,
			path: `apps/${row.pkg}`,
			size: 0,
			sha256: after,
			md5: "",
			verdict: "suspicious",
			reasonId: "cert-changed",
			detail: `${row.before.slice(0, 12)} → ${after.slice(0, 12)}`,
			permissions: [],
			packageName: row.pkg
		}], [{ idHint: row.pkg }]);
	}
}
function filesFromNative(kind, mode) {
	const native = kanafNative();
	if (!native) return Promise.resolve("absent");
	return new Promise((resolve) => {
		nativeWait = resolve;
		native.pick(kind, mode);
	});
}
var observer = null;
var booted = false;
function readIntegrity() {
	const native = kanafNative();
	if (!native?.integrity) return "unknown";
	const value = native.integrity();
	if (value === "ok" || value === "repacked") return value;
	return "unknown";
}
async function maybeRefreshFeeds() {
	const { settings, integrity } = useKanaf.getState();
	if (!settings.cloudFeeds) return;
	if (integrity === "repacked") {
		patch({ notice: "repacked" });
		return;
	}
	if (Date.now() - settings.lastFeeds < 864e5) return;
	await refreshSources(false);
}
async function boot() {
	if (booted) return;
	booted = true;
	const native = kanafNative();
	if (native?.shell?.() === "android") {
		let device = null;
		try {
			device = native.deviceStatus ? JSON.parse(native.deviceStatus()) : null;
		} catch {
			device = null;
		}
		const watching = native.watching?.() === "on";
		patch({
			shell: "android",
			device,
			realtime: watching,
			realtimeNote: watching ? "watching" : ""
		});
	}
	const [findings, vault, allow, log, meta, folders] = await Promise.all([
		idbAll("findings"),
		idbAll("quarantine"),
		idbAll("allow"),
		idbAll("log"),
		idbAll("meta"),
		idbAll("folders")
	]);
	const settingsRow = meta.find((row) => row.id === "settings");
	const trustedRow = meta.find((row) => row.id === "trusted");
	for (const folder of folders) if (folder.handle) rememberFolder(folder.id, folder.handle);
	const freshFindings = findings.filter((item) => {
		if (item.reasonId.startsWith("zip-") || item.reasonId === "size" || item.reasonId === "ratio") return false;
		if (/(?:^|\/)apps\/(com\.google\.|com\.android\.|android\.|com\.samsung\.|com\.sec\.|com\.microsoft\.|com\.facebook\.|com\.instagram\.|com\.whatsapp|org\.telegram\.|com\.twitter\.|com\.spotify\.|com\.snapchat\.|com\.amazon\.|com\.huawei\.|com\.xiaomi\.|com\.miui\.|com\.oppo\.|com\.coloros\.|com\.heytap\.|com\.oplus\.|com\.oneplus\.|com\.vivo\.|com\.realme\.|com\.sony\.|com\.lge\.|com\.motorola\.)/.test(item.path) && (item.reasonId === "heuristic" || item.reasonId === "archive-depth")) return false;
		if (item.reasonId !== "heuristic") return true;
		return [
			"overlay-accessibility",
			"sms-internet",
			"device-admin",
			"packer",
			"install-internet",
			"test-key"
		].some((id) => item.detail.includes(id));
	});
	if (freshFindings.length !== findings.length) await Promise.all(findings.filter((item) => !freshFindings.includes(item)).map((item) => idbDelete("findings", item.id)));
	patch({
		booted: true,
		findings: freshFindings.sort((a, b) => b.createdAt - a.createdAt),
		vault: vault.map(({ id, name, sha256, size, reasonId, createdAt }) => ({
			id,
			name,
			sha256,
			size,
			reasonId,
			createdAt
		})).sort((a, b) => b.createdAt - a.createdAt),
		allow,
		log: log.sort((a, b) => b.startedAt - a.startedAt).slice(0, 40),
		folders: folders.map(({ id, name }) => ({
			id,
			name
		})),
		settings: {
			...DEFAULT_SETTINGS,
			...settingsRow?.settings ?? {}
		},
		trusted: trustedRow?.trusted ?? useKanaf.getState().trusted,
		integrity: readIntegrity()
	});
	pushCallPolicy(useKanaf.getState().settings);
	await loadBundled();
	await drainNative();
	const loaded = useKanaf.getState().settings;
	if (!loaded.lastFeeds) await saveSettings({
		...loaded,
		lastFeeds: Date.now()
	});
	maybeScheduled();
}
async function parseHashChunked(text, db) {
	const lines = text.split("\n");
	const step = 5e3;
	for (let i = 0; i < lines.length; i += step) {
		parseHashTsv(lines.slice(i, i + step).join("\n"), db);
		await new Promise((resolve) => setTimeout(resolve, 0));
	}
}
async function fetchText(url, onBytes) {
	const response = await fetch(assetUrl(url));
	if (!response.ok || !response.body) throw new Error(String(response.status));
	const total = Number(response.headers.get("content-length") || 0);
	const reader = response.body.getReader();
	const chunks = [];
	let loaded = 0;
	for (;;) {
		const step = await reader.read();
		if (step.done) break;
		chunks.push(step.value);
		loaded += step.value.byteLength;
		onBytes?.(loaded, total);
	}
	return new Blob(chunks).text();
}
async function loadBundled() {
	patch({
		dbStatus: "loading",
		dbProgress: 0
	});
	try {
		const manifest = await (await fetch(assetUrl("/signatures/manifest.json"))).json();
		const db = emptyDb();
		db.builtAt = manifest.builtAt;
		db.sources = manifest.sources;
		const jobs = [
			{
				url: "/signatures/hashes.tsv",
				apply: (text) => parseHashChunked(text, db),
				weight: 70
			},
			{
				url: "/signatures/urls.txt",
				apply: (text) => {
					parseUrls(text, db);
				},
				weight: 18
			},
			{
				url: "/signatures/hosts.txt",
				apply: (text) => {
					parseHosts(text, db);
				},
				weight: 8
			},
			{
				url: "/signatures/certs.txt",
				apply: (text) => {
					parseCerts(text, db);
				},
				weight: 4
			}
		];
		let progress = 0;
		for (const job of jobs) {
			const text = await fetchText(job.url, (loaded, total) => {
				const inner = total ? loaded / total : 0;
				patch({ dbProgress: Math.round(progress + inner * job.weight) });
			});
			await job.apply(text);
			progress += job.weight;
			patch({ dbProgress: Math.round(progress) });
		}
		setDatabase(db);
		await applyStoredExtra(db);
		patch({
			dbStatus: "ready",
			dbProgress: 100,
			hashCount: db.hashRecords,
			sources: manifest.sources.map((source) => ({
				...source,
				state: source.count > 0 ? "ready" : "missing"
			}))
		});
	} catch (error) {
		patch({
			dbStatus: "error",
			notice: error instanceof Error ? error.message : "load"
		});
	}
}
function allowSet() {
	return new Set(useKanaf.getState().allow.map((item) => item.sha256));
}
async function addFindings(items, blobsFor) {
	const created = [];
	for (let i = 0; i < items.length; i++) {
		const finding = {
			...items[i],
			id: crypto.randomUUID(),
			createdAt: Date.now()
		};
		created.push(finding);
		await idbPut("findings", finding);
		const blob = blobsFor[i]?.bytes;
		if (blob) rememberBlob(finding.id, blob);
	}
	if (created.length === 0) return;
	patch({
		findings: [...created, ...useKanaf.getState().findings],
		lastClean: false
	});
	notifyWaiting(created.length);
}
async function notifyWaiting(count) {
	if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
	const note = new Notification("Kanaf", {
		body: String(count),
		tag: "kanaf-decision"
	});
	note.onclick = () => {
		window.focus();
		window.location.assign(assetUrl("/results"));
		note.close();
	};
}
async function scanFiles(mode, files) {
	if (useKanaf.getState().dbStatus !== "ready") return;
	if (useKanaf.getState().scan.running) return;
	resetCancel();
	const started = Date.now();
	const limits = mode === "quick" || mode === "scheduled" || mode === "live" ? QUICK_LIMITS : DEEP_LIMITS;
	let found = 0;
	let skipped = 0;
	const reports = [];
	const noteSkip = (name) => {
		if (mode === "custom") reports.push({
			name,
			size: 0,
			sha256: "",
			kind: "other",
			verdict: "skipped"
		});
	};
	patch({
		lastClean: false,
		notice: "",
		scan: {
			running: true,
			phase: "hash",
			mode,
			done: 0,
			total: files.length,
			current: "",
			found: 0,
			message: ""
		}
	});
	const db = getDatabase();
	const allow = allowSet();
	for (let i = 0; i < files.length; i++) {
		if (cancelled()) break;
		const file = files[i];
		patch({ scan: {
			...useKanaf.getState().scan,
			done: i,
			current: file.name,
			found
		} });
		let bytes = file.bytes;
		if (!bytes && file.url) try {
			const response = await fetch(file.url);
			if (!response.ok) {
				skipped++;
				noteSkip(file.name);
				continue;
			}
			bytes = new Uint8Array(await response.arrayBuffer());
		} catch {
			skipped++;
			noteSkip(file.name);
			continue;
		}
		if (!bytes) {
			skipped++;
			noteSkip(file.name);
			continue;
		}
		const cap = mode === "quick" || mode === "scheduled" || mode === "live" ? 67108864 : 50331648;
		if (bytes.byteLength > cap && !/\.(zip|apk|xapk|apks|jar)$/i.test(file.name)) {
			skipped++;
			noteSkip(file.name);
			continue;
		}
		if (bytes.byteLength > 100663296) {
			skipped++;
			noteSkip(file.name);
			continue;
		}
		try {
			const hits = await inspectBytes({
				name: file.name,
				path: file.path,
				bytes,
				db,
				allow,
				limits,
				markers: file.markers
			});
			if (hits.length) {
				found += hits.length;
				if (mode === "live" && hits.some((hit) => hit.reasonId === "hash-match" || hit.reasonId === "eicar" || hit.reasonId === "bad-cert")) kanafNative()?.note?.(file.name);
				await addFindings(hits.map((hit) => ({
					kind: "file",
					name: hit.name,
					path: hit.path,
					size: hit.size,
					sha256: hit.sha256,
					md5: hit.md5,
					verdict: hit.verdict,
					reasonId: hit.reasonId,
					detail: hit.detail,
					permissions: hit.permissions,
					folderId: file.folderId,
					segments: hit.path === file.path ? file.segments : void 0,
					packageName: hit.path === file.path ? file.packageName : void 0
				})), hits.map((hit) => ({
					idHint: hit.sha256,
					bytes: hit.path === file.path ? bytes : void 0
				})));
			}
			if (mode === "custom") {
				const verdict = hits.some((hit) => hit.verdict === "malicious") ? "malicious" : hits.length ? "suspicious" : "clean";
				reports.push({
					name: file.name,
					size: bytes.byteLength,
					sha256: hits[0]?.sha256 || (await hashBuffer(bytes)).sha256,
					kind: classify(file.name, bytes),
					verdict
				});
			}
		} catch {
			skipped++;
			noteSkip(file.name);
		}
		await new Promise((resolve) => setTimeout(resolve, 0));
	}
	const status = cancelled() ? "cancelled" : "done";
	const entry = {
		id: crypto.randomUUID(),
		mode,
		startedAt: started,
		finishedAt: Date.now(),
		files: files.length,
		findings: found,
		skipped,
		status
	};
	await idbPut("log", entry);
	patch({
		log: [entry, ...useKanaf.getState().log].slice(0, 40),
		lastClean: status === "done" && found === 0,
		lastScan: {
			files: files.length,
			findings: found,
			skipped,
			downloads: useKanaf.getState().lastScan?.downloads ?? null
		},
		...mode === "custom" ? { checked: reports } : {},
		scan: {
			running: false,
			phase: status === "cancelled" ? "cancelled" : "done",
			mode,
			done: files.length,
			total: files.length,
			current: "",
			found,
			message: ""
		}
	});
}
async function readHandleFile(handle) {
	const file = await handle.getFile();
	return new Uint8Array(await file.arrayBuffer());
}
async function walk(dir, prefix) {
	const out = [];
	const listing = dir;
	for await (const [name, handle] of listing.entries()) {
		if (cancelled()) break;
		if (handle.kind === "file") out.push({
			name,
			path: [...prefix, name].join("/"),
			segments: [...prefix, name],
			handle
		});
		else out.push(...await walk(handle, [...prefix, name]));
	}
	return out;
}
async function scanDirectory(mode, handle, folderId) {
	if (useKanaf.getState().scan.running) return;
	resetCancel();
	patch({ scan: {
		running: true,
		phase: "enum",
		mode,
		done: 0,
		total: 0,
		current: handle.name,
		found: 0,
		message: ""
	} });
	const listed = await walk(handle, []);
	const files = [];
	for (const item of listed) {
		if (cancelled()) break;
		const file = await item.handle.getFile();
		const limit = mode === "deep" ? 268435456 : 67108864;
		if (file.size > limit) continue;
		files.push({
			name: item.name,
			path: item.path,
			bytes: new Uint8Array(await file.arrayBuffer()),
			folderId,
			segments: item.segments
		});
	}
	const stopped = cancelled();
	patch({ scan: {
		...useKanaf.getState().scan,
		running: false,
		phase: "idle"
	} });
	if (stopped) return;
	await scanFiles(mode, files);
}
function cancelScan() {
	requestCancel();
}
async function pickDirectory(startIn) {
	const picker = window;
	if (!picker.showDirectoryPicker) return "unsupported";
	try {
		return await picker.showDirectoryPicker({
			mode: "readwrite",
			startIn
		});
	} catch {
		return null;
	}
}
async function filesFromInput(directory) {
	const input = document.createElement("input");
	input.type = "file";
	input.multiple = true;
	if (directory) input.setAttribute("webkitdirectory", "");
	const files = await new Promise((resolve) => {
		input.onchange = () => resolve([...input.files ?? []]);
		input.click();
	});
	const payload = [];
	for (const file of files) payload.push({
		name: file.name,
		path: file.webkitRelativePath || file.name,
		bytes: new Uint8Array(await file.arrayBuffer())
	});
	return payload;
}
async function chooseFolder(mode) {
	const native = await filesFromNative("folder", mode);
	if (native !== "absent") {
		if (!native?.length) {
			patch({ notice: "grant" });
			return;
		}
		await scanFiles(mode, native.map((file) => ({
			name: file.name,
			path: file.path || file.name,
			url: file.url
		})));
		return;
	}
	const picked = await pickDirectory(mode === "quick" ? "downloads" : "documents");
	if (picked && picked !== "unsupported") {
		const id = crypto.randomUUID();
		rememberFolder(id, picked);
		await scanDirectory(mode, picked, id);
		return;
	}
	if (picked === null) {
		patch({ notice: "grant" });
		return;
	}
	const payload = await filesFromInput(true);
	if (!payload.length) {
		patch({ notice: "grant" });
		return;
	}
	await scanFiles(mode, payload);
}
async function scanDevice(mode) {
	const native = kanafNative();
	if (!native?.listTargets) {
		await chooseFolder(mode);
		return;
	}
	let parsed;
	try {
		parsed = JSON.parse(native.listTargets(mode));
	} catch {
		patch({ notice: "nothing" });
		return;
	}
	const files = parsed.files ?? [];
	if (!files.length) {
		patch({ notice: "nothing" });
		return;
	}
	await maybeRefreshFeeds();
	patch({ lastScan: {
		files: 0,
		findings: 0,
		skipped: 0,
		downloads: parsed.downloads !== false
	} });
	await scanFiles(mode, files.map((file) => ({
		name: file.name,
		path: file.path || file.name,
		url: file.url,
		packageName: file.pkg,
		markers: file.perms
	})));
	if (parsed.downloads === false) patch({ lastScan: {
		...useKanaf.getState().lastScan ?? {
			files: files.length,
			findings: 0,
			skipped: 0,
			downloads: false
		},
		downloads: false
	} });
}
async function scanBehavior() {
	const native = kanafNative();
	if (!native?.listBehavior) return "web";
	let parsed;
	try {
		parsed = JSON.parse(native.listBehavior());
	} catch {
		return "fail";
	}
	const apps = parsed.apps ?? [];
	const scanned = typeof parsed.scanned === "number" ? parsed.scanned : apps.length;
	let hits = 0;
	for (const app of apps) {
		const pkg = app.pkg || "";
		const path = app.path || `apps/${pkg}`;
		const markers = [...app.perms ?? []];
		if (app.launcher) markers.push("android.intent.category.LAUNCHER");
		const judged = scoreBehavior({
			path,
			strings: markers
		});
		if (judged.band !== "suspicious") continue;
		hits++;
		if (useKanaf.getState().findings.some((item) => item.path === path && item.reasonId === "heuristic")) continue;
		const fingerprint = sha256Hex(new TextEncoder().encode(`behavior\n${path}`));
		await addFindings([{
			kind: "file",
			name: app.name || pkg,
			path,
			size: 0,
			sha256: fingerprint,
			md5: "",
			verdict: "suspicious",
			reasonId: "heuristic",
			detail: judged.reasons.join(","),
			permissions: judged.permissions,
			packageName: pkg
		}], [{ idHint: fingerprint }]);
	}
	return {
		scanned,
		hits
	};
}
async function readClipboard() {
	const native = kanafNative();
	if (native?.clipboard) return native.clipboard();
	try {
		return await navigator.clipboard.readText();
	} catch {
		return "";
	}
}
async function watchFolder() {
	const picked = await pickDirectory("downloads");
	if (!picked || picked === "unsupported") return false;
	const id = crypto.randomUUID();
	rememberFolder(id, picked);
	const item = {
		id,
		name: picked.name,
		handle: picked
	};
	await idbPut("folders", item);
	patch({ folders: [...useKanaf.getState().folders, {
		id,
		name: picked.name
	}] });
	return true;
}
async function removeFolder(id) {
	await idbDelete("folders", id);
	patch({ folders: useKanaf.getState().folders.filter((folder) => folder.id !== id) });
	if (useKanaf.getState().folders.length === 0) await setRealtime(false);
}
async function chooseFiles() {
	if (useKanaf.getState().scan.running || useKanaf.getState().dbStatus !== "ready") return "busy";
	const native = await filesFromNative("files", "custom");
	if (native !== "absent") {
		if (!native?.length) {
			patch({ notice: "nothing" });
			return "empty";
		}
		await scanFiles("custom", native.map((file) => ({
			name: file.name,
			path: file.path || file.name,
			url: file.url
		})));
		return (useKanaf.getState().lastScan?.findings ?? 0) > 0 ? "hit" : "clean";
	}
	const picker = window;
	if (picker.showOpenFilePicker) try {
		const handles = await picker.showOpenFilePicker({
			multiple: true,
			mode: "readwrite"
		});
		const files = [];
		for (const handle of handles) {
			const file = await handle.getFile();
			files.push({
				name: file.name,
				path: file.name,
				bytes: new Uint8Array(await file.arrayBuffer())
			});
		}
		if (!files.length) return "empty";
		await scanFiles("custom", files);
		return (useKanaf.getState().lastScan?.findings ?? 0) > 0 ? "hit" : "clean";
	} catch {
		return "empty";
	}
	const input = document.createElement("input");
	input.type = "file";
	input.multiple = true;
	const files = await new Promise((resolve) => {
		input.onchange = () => resolve([...input.files ?? []]);
		input.click();
	});
	const payload = [];
	for (const file of files) payload.push({
		name: file.name,
		path: file.name,
		bytes: new Uint8Array(await file.arrayBuffer())
	});
	if (!payload.length) {
		patch({ notice: "nothing" });
		return "empty";
	}
	await scanFiles("custom", payload);
	return (useKanaf.getState().lastScan?.findings ?? 0) > 0 ? "hit" : "clean";
}
async function allowFinding(id) {
	const finding = useKanaf.getState().findings.find((item) => item.id === id);
	if (!finding) return;
	const row = {
		id: finding.sha256 || finding.id,
		sha256: finding.sha256 || finding.id,
		name: finding.name,
		createdAt: Date.now()
	};
	await idbPut("allow", row);
	await idbDelete("findings", id);
	dropBlob(id);
	patch({
		allow: [row, ...useKanaf.getState().allow.filter((item) => item.sha256 !== row.sha256)],
		findings: useKanaf.getState().findings.filter((item) => item.id !== id),
		notice: "allowed"
	});
}
async function revokeAllow(id) {
	await idbDelete("allow", id);
	patch({ allow: useKanaf.getState().allow.filter((item) => item.id !== id) });
}
async function quarantineFinding(id) {
	const finding = useKanaf.getState().findings.find((item) => item.id === id);
	const bytes = takeBlob(id);
	if (!finding || !bytes) return "missing";
	await seal(bytes, {
		id: crypto.randomUUID(),
		name: finding.name,
		sha256: finding.sha256,
		size: bytes.byteLength,
		reasonId: finding.reasonId,
		createdAt: Date.now()
	});
	const removed = await deleteOriginal(finding);
	await idbDelete("findings", id);
	dropBlob(id);
	const vault = await idbAll("quarantine");
	patch({
		findings: useKanaf.getState().findings.filter((item) => item.id !== id),
		vault: vault.map(({ id: vid, name, sha256, size, reasonId, createdAt }) => ({
			id: vid,
			name,
			sha256,
			size,
			reasonId,
			createdAt
		})),
		notice: removed ? "moved" : "remains"
	});
	return removed ? "moved" : "copied";
}
async function deleteOriginal(finding) {
	if (!finding.folderId || !finding.segments?.length) return false;
	const root = folderHandle(finding.folderId);
	if (!root) return false;
	try {
		let dir = root;
		for (let i = 0; i < finding.segments.length - 1; i++) dir = await dir.getDirectoryHandle(finding.segments[i]);
		await dir.removeEntry(finding.segments[finding.segments.length - 1]);
		return true;
	} catch {
		return false;
	}
}
async function deleteFinding(id) {
	const finding = useKanaf.getState().findings.find((item) => item.id === id);
	if (!finding) return false;
	if (finding.packageName && kanafNative()?.uninstall) {
		kanafNative()?.uninstall?.(finding.packageName);
		patch({ notice: "uninstall" });
		return false;
	}
	if (!await deleteOriginal(finding)) {
		patch({ notice: "delete-blocked" });
		return false;
	}
	await idbDelete("findings", id);
	dropBlob(id);
	patch({
		findings: useKanaf.getState().findings.filter((item) => item.id !== id),
		notice: "deleted"
	});
	return true;
}
async function restoreVault(id) {
	const row = (await idbAll("quarantine")).find((item) => item.id === id);
	if (!row) return;
	const bytes = await openVault(row);
	const blob = new Blob([bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)]);
	const url = URL.createObjectURL(blob);
	const link = document.createElement("a");
	link.href = url;
	link.download = row.name;
	link.click();
	URL.revokeObjectURL(url);
}
async function purgeVault(id) {
	await destroyVault(id);
	patch({ vault: useKanaf.getState().vault.filter((item) => item.id !== id) });
}
async function scanLink(raw) {
	return analyzeUrl(raw, getDatabase());
}
async function rememberUrl(raw) {
	const norm = normalizeUrl(raw);
	if (!norm) return;
	const row = {
		id: norm.href,
		sha256: norm.href,
		name: norm.href,
		createdAt: Date.now()
	};
	await idbPut("allow", row);
	patch({ allow: [row, ...useKanaf.getState().allow] });
}
function inspectMessage(sender, text) {
	const db = getDatabase();
	const trusted = useKanaf.getState().trusted;
	const result = analyzeMessage({
		sender,
		text,
		trusted,
		official: useKanaf.getState().settings.officialNumbers.map((row) => row.e164),
		db: {
			hosts: db.hosts,
			urls: db.urls
		}
	});
	const fingerprint = sha256Hex(new TextEncoder().encode(`${sender}\n${text}`));
	return {
		...result,
		fingerprint
	};
}
async function scanInbox(onProgress) {
	const native = kanafNative();
	if (!native?.listMessages) return {
		status: "web",
		scanned: 0,
		hits: []
	};
	let parsed = readInbox(native.listMessages());
	if (parsed.status === "need") {
		if (!await askSms()) return {
			status: "denied",
			scanned: 0,
			hits: []
		};
		parsed = readInbox(native.listMessages());
	}
	if (parsed.status !== "ok") return {
		status: parsed.status === "denied" ? "denied" : "empty",
		scanned: 0,
		hits: []
	};
	const messages = parsed.messages ?? [];
	if (!messages.length) return {
		status: "empty",
		scanned: 0,
		hits: []
	};
	const hits = [];
	const db = getDatabase();
	const allow = allowSet();
	for (let i = 0; i < messages.length; i++) {
		onProgress?.(i, messages.length);
		const message = messages[i];
		const from = message?.from || "";
		const body = message?.body || "";
		if (body) {
			const result = inspectMessage(from, body);
			if (result.verdict !== "clean") {
				const detail = result.clause || result.urls.find((url) => url.hint)?.hint || result.urls.find((url) => url.verdict !== "clean")?.host || result.phones.find((phone) => phone.verdict !== "clean")?.e164 || result.reasons[0] || "";
				hits.push({
					from,
					verdict: result.verdict,
					reasons: result.reasons,
					detail,
					excerpt: body.slice(0, 180)
				});
				if (!useKanaf.getState().findings.some((item) => item.sha256 === result.fingerprint)) await keepMessageFinding(from, result.fingerprint, result.reasons[0] || "listed", detail, result.verdict);
			}
		}
		for (const file of message?.files ?? []) {
			if (!file?.url || !file.name) continue;
			try {
				const response = await fetch(file.url);
				if (!response.ok) continue;
				const bytes = new Uint8Array(await response.arrayBuffer());
				const found = await inspectBytes({
					name: file.name,
					path: `mms/${from}/${file.name}`,
					bytes,
					db,
					allow,
					limits: QUICK_LIMITS
				});
				for (const hit of found) {
					hits.push({
						from,
						verdict: hit.verdict,
						reasons: [hit.reasonId],
						detail: hit.detail || file.name,
						excerpt: body.slice(0, 180),
						file: file.name
					});
					if (!useKanaf.getState().findings.some((item) => item.sha256 === hit.sha256 && item.reasonId === hit.reasonId)) await addFindings([{
						kind: "file",
						name: file.name,
						path: `mms/${from}/${file.name}`,
						size: hit.size,
						sha256: hit.sha256,
						md5: hit.md5,
						verdict: hit.verdict,
						reasonId: hit.reasonId,
						detail: hit.detail,
						permissions: hit.permissions
					}], [{
						idHint: hit.sha256,
						bytes: bytes.byteLength <= 8388608 ? bytes : void 0
					}]);
				}
			} catch {}
		}
	}
	onProgress?.(messages.length, messages.length);
	return {
		status: "ok",
		scanned: messages.length,
		hits
	};
}
function readInbox(raw) {
	try {
		const parsed = JSON.parse(raw);
		return {
			status: parsed.status || "empty",
			messages: parsed.messages
		};
	} catch {
		return { status: "denied" };
	}
}
async function askSms() {
	const native = kanafNative();
	if (!native?.askSms) return false;
	return new Promise((resolve) => {
		const timer = window.setTimeout(() => {
			permWait = null;
			resolve(false);
		}, 3e4);
		permWait = (ok) => {
			window.clearTimeout(timer);
			resolve(ok);
		};
		native.askSms();
	});
}
async function keepMessageFinding(sender, fingerprint, reasonId, detail, verdict) {
	await addFindings([{
		kind: "message",
		name: sender || fingerprint.slice(0, 12),
		path: fingerprint,
		size: 0,
		sha256: fingerprint,
		md5: "",
		verdict,
		reasonId,
		detail,
		permissions: [],
		sender
	}], []);
}
async function runEicar() {
	await scanFiles("custom", [{
		name: "eicar.com",
		path: "eicar.com",
		bytes: eicarBytes()
	}]);
	return useKanaf.getState().findings.some((item) => item.reasonId === "eicar");
}
async function saveSettings(settings) {
	const next = {
		...DEFAULT_SETTINGS,
		...settings,
		officialNumbers: settings.officialNumbers ?? [],
		blockedNumbers: settings.blockedNumbers ?? []
	};
	patch({ settings: next });
	pushCallPolicy(next);
	await idbPut("meta", {
		id: "settings",
		settings: next
	});
}
function pushCallPolicy(settings) {
	kanafNative()?.setCallPolicy?.(JSON.stringify({
		official: settings.officialNumbers.map((row) => row.e164),
		blocked: settings.blockedNumbers
	}));
}
function exportDecisions() {
	const { findings, log } = useKanaf.getState();
	const lines = [
		"Kanaf decisions",
		(/* @__PURE__ */ new Date()).toISOString(),
		""
	];
	for (const entry of log) lines.push(`scan ${entry.mode} ${entry.status} files=${entry.files} findings=${entry.findings}`);
	lines.push("");
	for (const item of findings) lines.push(`${item.verdict}\t${item.reasonId}\t${item.name}\t${item.detail}`);
	return lines.join("\n");
}
async function saveDecisions() {
	const text = exportDecisions();
	if (!useKanaf.getState().findings.length && !useKanaf.getState().log.length) return "empty";
	const native = kanafNative();
	if (native?.saveText) return native.saveText("kanaf-decisions.txt", text) === "ok" ? "ok" : "fail";
	const blob = new Blob([text], { type: "text/plain" });
	const url = URL.createObjectURL(blob);
	const link = document.createElement("a");
	link.href = url;
	link.download = "kanaf-decisions.txt";
	link.click();
	URL.revokeObjectURL(url);
	return "web";
}
async function setRealtime(on) {
	const native = kanafNative();
	if (native?.setWatch) {
		if (!on) {
			native.setWatch(false);
			patch({
				realtime: false,
				realtimeNote: "off"
			});
			return "off";
		}
		if (!await askNativeNotify()) {
			native.setWatch(false);
			patch({
				realtime: false,
				realtimeNote: "need"
			});
			return "need";
		}
		if (native.setWatch(true) === "fail") {
			patch({
				realtime: false,
				realtimeNote: "fail"
			});
			return "fail";
		}
		patch({
			realtime: true,
			realtimeNote: "watching"
		});
		return "watching";
	}
	if (!on) {
		observer?.disconnect();
		observer = null;
		patch({
			realtime: false,
			realtimeNote: "off"
		});
		return "off";
	}
	if (typeof Notification !== "undefined" && Notification.permission !== "granted") {
		if (await Notification.requestPermission() !== "granted") {
			patch({
				realtime: false,
				realtimeNote: "need"
			});
			return "need";
		}
	}
	const picker = window;
	if (!picker.FileSystemObserver) {
		patch({
			realtime: false,
			realtimeNote: "missing"
		});
		return "missing";
	}
	let folder = useKanaf.getState().folders[0];
	if (!folder) {
		if (!await watchFolder()) {
			patch({
				realtime: false,
				realtimeNote: "pick"
			});
			return "pick";
		}
		folder = useKanaf.getState().folders[0];
	}
	const handle = folder ? folderHandle(folder.id) : void 0;
	if (!handle || !folder) {
		patch({
			realtime: false,
			realtimeNote: "missing"
		});
		return "missing";
	}
	const live = new picker.FileSystemObserver((records) => {
		for (const record of records) {
			const changed = record.changedHandle;
			if (changed && changed.kind === "file") readHandleFile(changed).then((bytes) => scanFiles("live", [{
				name: changed.name,
				path: changed.name,
				bytes,
				folderId: folder?.id,
				segments: [changed.name]
			}]));
		}
	});
	await live.observe(handle, { recursive: true });
	observer = live;
	patch({
		realtime: true,
		realtimeNote: "watching"
	});
	return "watching";
}
async function askNativeNotify() {
	const native = kanafNative();
	if (!native || typeof native.askNotify !== "function") return true;
	return new Promise((resolve) => {
		const timer = window.setTimeout(() => {
			permWait = null;
			resolve(false);
		}, 2e4);
		permWait = (ok) => {
			window.clearTimeout(timer);
			resolve(ok);
		};
		native.askNotify();
	});
}
async function charging() {
	const batteryApi = navigator;
	if (!batteryApi.getBattery) return true;
	try {
		return (await batteryApi.getBattery()).charging;
	} catch {
		return true;
	}
}
async function maybeScheduled() {
	const { settings, folders, scan } = useKanaf.getState();
	if (!settings.scheduleEnabled || scan.running || folders.length === 0) return;
	const span = settings.every === "week" ? 6048e5 : 864e5;
	if (Date.now() - settings.lastScheduled < span) return;
	if (settings.chargingOnly && !await charging()) {
		patch({ notice: "charging" });
		return;
	}
	if (kanafNative()?.listTargets) {
		await saveSettings({
			...settings,
			lastScheduled: Date.now()
		});
		await scanDevice("quick");
		return;
	}
	const folder = folders[0];
	const handle = folderHandle(folder.id);
	if (!handle) return;
	await saveSettings({
		...settings,
		lastScheduled: Date.now()
	});
	await scanDirectory("scheduled", handle, folder.id);
}
function metered() {
	const native = kanafNative();
	if (native?.network) {
		const kind = native.network();
		if (kind === "cellular") return true;
		if (kind === "wifi" || kind === "ethernet") return false;
		if (kind === "none") return false;
	}
	const connection = navigator.connection;
	if (!connection) return null;
	if (connection.saveData) return true;
	if (connection.type === "cellular") return true;
	if (connection.type === "wifi" || connection.type === "ethernet") return false;
	return null;
}
function networkKind() {
	const native = kanafNative();
	if (native?.network) {
		const kind = native.network();
		if (kind === "wifi" || kind === "ethernet") return "wifi";
		if (kind === "cellular") return "cellular";
		if (kind === "none") return "none";
	}
	const meteredNow = metered();
	if (meteredNow === true) return "cellular";
	if (meteredNow === false) return "wifi";
	return "unknown";
}
function openDeviceSettings(kind) {
	kanafNative()?.openSettings?.(kind);
}
async function pullNative(url) {
	const native = kanafNative();
	if (!native || typeof native.fetchUrl !== "function") throw new Error("download unavailable");
	const id = crypto.randomUUID();
	if (!await new Promise((resolve) => {
		const timer = window.setTimeout(() => {
			netWait = null;
			resolve(false);
		}, 18e4);
		const previous = netWait;
		netWait = (got, success) => {
			if (got !== id) {
				previous?.(got, success);
				return;
			}
			window.clearTimeout(timer);
			netWait = null;
			resolve(success);
		};
		netStatus = "";
		native.fetchUrl(id, url);
	})) throw new Error(netStatus || "download failed");
	const response = await fetch(`https://appassets.androidplatform.net/__net/${encodeURIComponent(id)}`);
	if (!response.ok) throw new Error("download missing");
	return new Uint8Array(await response.arrayBuffer());
}
function textOf(bytes) {
	return new TextDecoder().decode(bytes);
}
var FEED_PARTS = [
	"urlhaus",
	"malwarebazaar",
	"cscb",
	"clamav-daily",
	"threatfox",
	"feodo",
	"openphish",
	"et-open"
];
function freshHashLines(text, db) {
	const out = [];
	for (const line of text.split("\n")) {
		if (!line) continue;
		const [kind, hash] = line.split("	");
		if (kind !== "md5" && kind !== "sha1" && kind !== "sha256") continue;
		if (!hash) continue;
		if (db.hashes.has(`${kind}:${hash.toLowerCase()}`)) continue;
		out.push(line);
	}
	return out;
}
function keepHashes(text, db, sink) {
	const fresh = freshHashLines(text, db);
	sink.push(...fresh);
	return parseHashTsv(fresh.join("\n"), db);
}
function keepUrls(text, db, sink) {
	const fresh = [];
	for (const line of text.split("\n")) {
		const url = line.trim();
		if (!url || url.startsWith("#") || db.urls.has(url)) continue;
		fresh.push(url);
	}
	sink.push(...fresh.map((url) => `U ${url}`));
	return parseUrls(fresh.join("\n"), db);
}
function keepHosts(text, db, sink) {
	const fresh = [];
	for (const line of text.split("\n")) {
		const host = line.trim().toLowerCase();
		if (!host || host.startsWith("#") || db.hosts.has(host)) continue;
		fresh.push(host);
	}
	sink.push(...fresh.map((host) => `H ${host}`));
	return parseHosts(fresh.join("\n"), db);
}
function keepCerts(text, db, sink) {
	const fresh = [];
	for (const line of text.split("\n")) {
		const thumb = line.split("	")[0] ?? "";
		if (!/^[0-9a-f]{64}$/.test(thumb) || db.certs.has(thumb)) continue;
		fresh.push(line);
	}
	sink.push(...fresh.map((line) => `C ${line}`));
	return parseCerts(fresh.join("\n"), db);
}
function keepFeed(text, db, sink) {
	const urls = [];
	const hosts = [];
	const hashes = [];
	for (const line of text.split("\n")) if (line.startsWith("U ")) urls.push(line.slice(2).trim());
	else if (line.startsWith("H ")) hosts.push(line.slice(2).trim());
	else if (/^(md5|sha1|sha256)\t/.test(line)) hashes.push(line);
	return keepUrls(urls.join("\n"), db, sink) + keepHosts(hosts.join("\n"), db, sink) + keepHashes(hashes.join("\n"), db, sink);
}
async function readFeedExtra() {
	return (await idbAll("meta")).find((row) => row.id === "feed-extra")?.body ?? "";
}
async function applyStoredExtra(db) {
	let body = "";
	try {
		body = await readFeedExtra();
	} catch {
		return;
	}
	if (!body) return;
	const hashes = [];
	const urls = [];
	const hosts = [];
	const certs = [];
	for (const line of body.split("\n")) if (line.startsWith("U ")) urls.push(line.slice(2));
	else if (line.startsWith("H ")) hosts.push(line.slice(2));
	else if (line.startsWith("C ")) certs.push(line.slice(2));
	else if (line) hashes.push(line);
	if (hashes.length) parseHashTsv(hashes.join("\n"), db);
	if (urls.length) parseUrls(urls.join("\n"), db);
	if (hosts.length) parseHosts(hosts.join("\n"), db);
	if (certs.length) parseCerts(certs.join("\n"), db);
}
async function saveFeedExtra(chunk) {
	const trimmed = chunk.trim();
	if (!trimmed) return;
	const merged = /* @__PURE__ */ new Set();
	const prev = await readFeedExtra();
	if (prev) {
		for (const line of prev.split("\n")) if (line) merged.add(line);
	}
	for (const line of trimmed.split("\n")) if (line) merged.add(line);
	await idbPut("meta", {
		id: "feed-extra",
		body: [...merged].join("\n")
	});
}
function ingestExtra(part, raw) {
	if (part === "threatfox") return threatFoxToFeed(raw);
	if (part === "feodo" || part === "et-open") return ipsToFeed(raw);
	if (part === "openphish") return urlsToFeed(raw);
	return "";
}
async function refreshOnDevice() {
	const parts = FEED_PARTS;
	const db = getDatabase();
	const failedIds = [];
	const extra = [];
	for (let i = 0; i < parts.length; i++) {
		const part = parts[i];
		patch({
			dbProgress: Math.round(i / parts.length * 100),
			sources: useKanaf.getState().sources.map((source) => source.id === part ? {
				...source,
				state: "loading",
				error: void 0
			} : source)
		});
		try {
			let added = 0;
			if (part === "urlhaus") {
				const raw = textOf(await pullNative("https://urlhaus.abuse.ch/downloads/text/"));
				const lines = [];
				const hosts = [];
				for (const line of raw.split("\n")) {
					const norm = normalizeUrl(line);
					if (!norm) continue;
					lines.push(norm.href);
					hosts.push(norm.hostname);
				}
				added = keepUrls(lines.join("\n"), db, extra);
				keepHosts(hosts.join("\n"), db, extra);
			} else if (part === "malwarebazaar") {
				const sha = await pullNative("https://bazaar.abuse.ch/export/txt/sha256/recent/");
				const md5 = await pullNative("https://bazaar.abuse.ch/export/txt/md5/recent/");
				const rows = [];
				for (const line of textOf(sha).split("\n")) {
					const hash = line.trim().toLowerCase();
					if (/^[0-9a-f]{64}$/.test(hash)) rows.push(`sha256\t${hash}\t*\tmalwarebazaar\tMalwareBazaar-recent`);
				}
				for (const line of textOf(md5).split("\n")) {
					const hash = line.trim().toLowerCase();
					if (/^[0-9a-f]{32}$/.test(hash)) rows.push(`md5\t${hash}\t*\tmalwarebazaar\tMalwareBazaar-recent`);
				}
				added = keepHashes(rows.join("\n"), db, extra);
			} else if (part === "cscb") {
				const raw = textOf(await pullNative("https://bazaar.abuse.ch/export/csv/cscb/"));
				const rows = [];
				for (const line of raw.split("\n")) {
					if (!line || line.startsWith("#") || line.startsWith("\"time")) continue;
					const cols = line.split(",");
					const thumb = (cols[2] || "").replaceAll("\"", "").trim().toLowerCase();
					const reason = (cols[8] || "CSCB").replaceAll("\"", "").trim();
					if (/^[0-9a-f]{64}$/.test(thumb)) rows.push(`${thumb}\t${reason}`);
				}
				added = keepCerts(rows.join("\n"), db, extra);
			} else if (part === "threatfox" || part === "feodo" || part === "openphish" || part === "et-open") added = keepFeed(ingestExtra(part, textOf(await pullNative(part === "threatfox" ? "https://threatfox.abuse.ch/export/csv/recent/" : part === "feodo" ? "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" : part === "openphish" ? "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt" : "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"))), db, extra);
			else {
				let parsed = null;
				let last = "unavailable";
				for (const url of ["https://database.clamav.net/daily.cvd", "https://packages.microsoft.com/clamav/daily.cvd"]) try {
					parsed = await parseCvd(await pullNative(url));
					break;
				} catch (error) {
					last = error instanceof Error ? error.message : "cvd";
				}
				if (!parsed) throw new Error(last);
				added = keepHashes(parsed.records.map((record) => `${record.kind}\t${record.hash}\t${record.size ?? "*"}\tclamav-daily\t${record.name.replaceAll("	", " ")}`).join("\n"), db, extra);
			}
			patch({ sources: useKanaf.getState().sources.map((source) => source.id === part ? {
				...source,
				state: "ready",
				count: added || source.count,
				updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
				error: void 0
			} : source) });
		} catch (error) {
			const why = error instanceof Error && error.message ? error.message.slice(0, 40) : "";
			failedIds.push(why ? `${part} ${why}` : part);
			patch({ sources: useKanaf.getState().sources.map((source) => source.id === part ? {
				...source,
				state: "failed",
				error: error instanceof Error ? error.message : "failed"
			} : source) });
		}
	}
	setDatabase(db);
	try {
		await saveFeedExtra(extra.join("\n"));
	} catch {}
	patch({
		hashCount: db.hashRecords,
		dbProgress: 100,
		notice: failedIds.length ? "" : "update-ok"
	});
	if (!failedIds.length) await saveSettings({
		...useKanaf.getState().settings,
		lastFeeds: Date.now()
	});
}
async function refreshSources(forceCellular) {
	const { settings, dbStatus, integrity } = useKanaf.getState();
	if (dbStatus !== "ready") return;
	if (integrity === "repacked") {
		patch({ notice: "repacked" });
		return;
	}
	if (settings.wifiOnly && !forceCellular && metered() === true) {
		patch({ notice: "cellular" });
		return;
	}
	if (kanafNative()?.fetchUrl) {
		await refreshOnDevice();
		return;
	}
	const parts = FEED_PARTS;
	const db = getDatabase();
	const failedIds = [];
	const extra = [];
	for (let i = 0; i < parts.length; i++) {
		const part = parts[i];
		patch({
			dbProgress: Math.round(i / parts.length * 100),
			sources: useKanaf.getState().sources.map((source) => source.id === part || part === "urlhaus" && source.id === "urlhaus" ? {
				...source,
				state: "loading"
			} : source)
		});
		try {
			const response = await fetch(assetUrl(`/api/signatures?part=${part}`));
			if (!response.ok) throw new Error(await response.text());
			const text = await response.text();
			if (part === "urlhaus") {
				const hosts = [];
				for (const line of text.split("\n")) try {
					hosts.push(new URL(line.trim()).hostname);
				} catch {}
				keepUrls(text, db, extra);
				keepHosts(hosts.join("\n"), db, extra);
			} else if (part === "cscb") keepCerts(text, db, extra);
			else if (part === "threatfox" || part === "feodo" || part === "openphish" || part === "et-open") keepFeed(text, db, extra);
			else keepHashes(text, db, extra);
			patch({ sources: useKanaf.getState().sources.map((source) => source.id === part ? {
				...source,
				state: "ready",
				updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
				error: void 0
			} : source) });
		} catch (error) {
			const why = error instanceof Error && error.message ? error.message.slice(0, 40) : "";
			failedIds.push(why ? `${part} ${why}` : part);
			patch({ sources: useKanaf.getState().sources.map((source) => source.id === part ? {
				...source,
				state: "failed",
				error: error instanceof Error ? error.message : "failed"
			} : source) });
		}
	}
	setDatabase(db);
	try {
		await saveFeedExtra(extra.join("\n"));
	} catch {}
	patch({
		hashCount: db.hashRecords,
		dbProgress: 100,
		notice: failedIds.length ? "" : "update-ok"
	});
	if (!failedIds.length) await saveSettings({
		...useKanaf.getState().settings,
		lastFeeds: Date.now()
	});
}
async function askCloud(text, key) {
	const secret = key.trim();
	if (!secret) return "need";
	const body = text.trim().slice(0, 2e3);
	if (!body) return "fail";
	try {
		const response = await fetch("https://api.x.ai/v1/chat/completions", {
			method: "POST",
			headers: {
				"content-type": "application/json",
				authorization: `Bearer ${secret}`
			},
			body: JSON.stringify({
				model: "grok-3-mini",
				temperature: 0,
				messages: [{
					role: "system",
					content: "Judge one pasted message for phishing. Reply with two lines only.\nVERDICT: suspicious or clean\nSENTENCE: the short clause you relied on, or -"
				}, {
					role: "user",
					content: body
				}]
			})
		});
		if (!response.ok) return "fail";
		const content = (await response.json()).choices?.[0]?.message?.content || "";
		const line = content.match(/VERDICT:\s*(suspicious|clean)/i)?.[1]?.toLowerCase();
		const sentence = content.match(/SENTENCE:\s*(.+)/i)?.[1]?.trim() || "";
		return {
			verdict: line === "suspicious" ? "suspicious" : "clean",
			clause: sentence === "-" ? "" : sentence.slice(0, 180)
		};
	} catch {
		return "fail";
	}
}
async function tryRedirect(raw) {
	const norm = normalizeUrl(raw);
	if (!norm) return { ok: false };
	try {
		return {
			ok: true,
			final: (await fetch(norm.href, {
				method: "GET",
				redirect: "follow"
			})).url || norm.href
		};
	} catch {
		return { ok: false };
	}
}
function Boot() {
	(0, import_react.useEffect)(() => {
		boot();
	}, []);
	return null;
}
function Shield({ large = false }) {
	const id = (0, import_react.useId)().replace(/:/g, "");
	const { t } = useI18n();
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("svg", {
		viewBox: "0 0 120 140",
		className: large ? "h-12 w-10 shrink-0" : "h-8 w-7",
		role: "img",
		"aria-label": t.ariaShield,
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("defs", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("linearGradient", {
				id,
				x1: "0",
				y1: "0",
				x2: "0",
				y2: "1",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("stop", {
					offset: "0%",
					stopColor: "#1a3d5c"
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("stop", {
					offset: "100%",
					stopColor: "#07111f"
				})]
			}) }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("path", {
				d: "M60 6 108 28v40c0 32-20 54-48 66C32 122 12 100 12 68V28Z",
				fill: `url(#${id})`,
				stroke: "#E7C27A",
				strokeOpacity: "0.45",
				strokeWidth: "2"
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("path", {
				className: large ? "shield-k" : void 0,
				d: "M46 46h10v16l14-16h13L63 70l22 26H72L58 76v20H46Z",
				fill: "#5CE1FF"
			})
		]
	});
}
function Frame({ children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: "mx-auto min-h-screen w-full max-w-md px-4 pb-10 pt-4",
		children
	});
}
function TopBar({ title }) {
	const { t } = useI18n();
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("header", {
		className: "mb-5 flex min-h-12 items-center gap-2",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
				to: "/",
				className: "inline-flex h-10 shrink-0 items-center justify-center rounded-full px-2 text-sm font-medium text-gold",
				children: t.back
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", {
				className: "min-w-0 flex-1 truncate text-center text-base font-semibold",
				children: title
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", {
				className: "shrink-0",
				children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Shield, {})
			})
		]
	});
}
function HomeBar() {
	const { t, toggle, locale } = useI18n();
	const count = useKanaf((s) => s.hashCount);
	const ready = useKanaf((s) => s.dbStatus === "ready");
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("header", {
		className: "mb-4 flex items-center gap-3",
		children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Shield, { large: true }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "min-w-0 flex-1",
				children: [
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", {
						className: "text-lg font-semibold leading-none",
						children: t.name
					}),
					/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1 text-xs leading-snug text-muted",
						children: t.tagline
					}),
					ready ? /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "mt-1 text-[11px] text-cyan",
						children: signatureLabel(locale, count)
					}) : null
				]
			}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
				type: "button",
				onClick: toggle,
				className: "inline-flex h-8 shrink-0 items-center justify-center rounded-full border border-line px-3 text-xs font-semibold text-gold",
				children: t.lang
			})
		]
	});
}
function Notice() {
	const notice = useKanaf((s) => s.notice);
	const { t } = useI18n();
	if (!notice) return null;
	const namedFail = notice.startsWith("update-fail:");
	const map = {
		grant: t.grant,
		nothing: t.nothing,
		allowed: t.allowedDone,
		moved: t.moved,
		remains: t.originalRemains,
		"delete-blocked": t.deleteBlocked,
		deleted: t.yesDelete,
		cellular: t.cellularBlocked,
		"update-fail": t.updateFail,
		"update-ok": t.updateOk,
		charging: t.chargingSkip,
		uninstall: t.uninstallAsked,
		repacked: t.integrityBad
	};
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
		className: "glass mb-3 px-4 py-3 text-sm text-fg",
		role: "status",
		children: namedFail ? `${t.updateFail} ${notice.slice(12)}` : map[notice] ?? notice
	});
}
function Confirm({ title, body, confirm, danger, onConfirm, onClose }) {
	const { t } = useI18n();
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
		className: "fixed inset-0 z-20 flex items-end justify-center bg-ink/70 p-4 sm:items-center",
		role: "presentation",
		children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
			role: "dialog",
			"aria-modal": "true",
			"aria-labelledby": "confirm-title",
			className: "glass w-full max-w-md p-5",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
					id: "confirm-title",
					className: "text-lg font-semibold",
					children: title
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
					className: "mt-2 text-sm leading-relaxed text-muted",
					children: body
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "mt-5 flex gap-3",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						onClick: onClose,
						className: "min-h-12 flex-1 rounded-2xl border border-line text-sm",
						children: t.close
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("button", {
						type: "button",
						onClick: onConfirm,
						className: danger ? "min-h-12 flex-1 rounded-2xl bg-danger text-sm font-semibold text-fg" : "min-h-12 flex-1 rounded-2xl bg-teal text-sm font-semibold text-teal-ink",
						children: confirm
					})]
				})
			]
		})
	});
}
function Bidi({ children }) {
	return /* @__PURE__ */ (0, import_jsx_runtime.jsx)("bdi", {
		className: "break-all font-medium text-cyan",
		children
	});
}
var styles_default = "/assets/styles-CG1fSXyD.css";
var Route$23 = createRootRoute({
	head: () => ({
		meta: [
			{ charSet: "utf-8" },
			{
				name: "viewport",
				content: "width=device-width, initial-scale=1"
			},
			{ title: "Kanaf" },
			{
				name: "theme-color",
				content: "#07111F"
			},
			{
				name: "description",
				content: "Kanaf — scan your device. The decision is yours."
			}
		],
		links: [
			{
				rel: "icon",
				type: "image/svg+xml",
				href: "/favicon.svg"
			},
			{
				rel: "stylesheet",
				href: styles_default
			},
			{
				rel: "manifest",
				href: "/__grok/manifest.webmanifest"
			},
			{
				rel: "apple-touch-icon",
				href: "/__grok/icon-180.png"
			}
		]
	}),
	component: () => /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("html", {
		lang: "en",
		suppressHydrationWarning: true,
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("head", { children: /* @__PURE__ */ (0, import_jsx_runtime.jsx)(HeadContent, {}) }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("body", { children: [
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(PreviewHostBridge, {}),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(AuthProvider, { children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(LocaleProvider, { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Boot, {}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Outlet, {})] }) }),
			/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Scripts, {})
		] })]
	})
});
var $$splitComponentImporter$21 = () => import("./routes-WZQ1s7Lh.mjs");
var Route$22 = createFileRoute("/")({ component: lazyRouteComponent($$splitComponentImporter$21, "component") });
var $$splitComponentImporter$20 = () => import("./advisor-B9yD_hwx.mjs");
var Route$21 = createFileRoute("/advisor")({ component: lazyRouteComponent($$splitComponentImporter$20, "component") });
var $$splitComponentImporter$19 = () => import("./behavior-B5tqXg0t.mjs");
var Route$20 = createFileRoute("/behavior")({ component: lazyRouteComponent($$splitComponentImporter$19, "component") });
var $$splitComponentImporter$18 = () => import("./checked-DQgCsZhy.mjs");
var Route$19 = createFileRoute("/checked")({ component: lazyRouteComponent($$splitComponentImporter$18, "component") });
var $$splitComponentImporter$17 = () => import("./link-DREBrQFv.mjs");
var Route$18 = createFileRoute("/link")({
	validateSearch: (search) => ({ url: typeof search.url === "string" ? search.url : "" }),
	component: lazyRouteComponent($$splitComponentImporter$17, "component")
});
var $$splitComponentImporter$16 = () => import("./messages-Dad85VIo.mjs");
var Route$17 = createFileRoute("/messages")({
	validateSearch: (search) => ({ auto: search.auto === true || search.auto === "1" || search.auto === "true" || search.auto === 1 }),
	component: lazyRouteComponent($$splitComponentImporter$16, "component")
});
var $$splitComponentImporter$15 = () => import("./phish-CGiCvrpm.mjs");
var Route$16 = createFileRoute("/phish")({
	validateSearch: (search) => ({ text: typeof search.text === "string" ? search.text : "" }),
	component: lazyRouteComponent($$splitComponentImporter$15, "component")
});
var $$splitComponentImporter$14 = () => import("./privacy-DWl5H_an.mjs");
var Route$15 = createFileRoute("/privacy")({ component: lazyRouteComponent($$splitComponentImporter$14, "component") });
var $$splitComponentImporter$13 = () => import("./qr-CHu8oWBC.mjs");
var Route$14 = createFileRoute("/qr")({ component: lazyRouteComponent($$splitComponentImporter$13, "component") });
var $$splitComponentImporter$12 = () => import("./quarantine-BlOnJy8P.mjs");
var Route$13 = createFileRoute("/quarantine")({ component: lazyRouteComponent($$splitComponentImporter$12, "component") });
var $$splitComponentImporter$11 = () => import("./results-BoQuUELV.mjs");
var Route$12 = createFileRoute("/results")({ component: lazyRouteComponent($$splitComponentImporter$11, "component") });
var $$splitComponentImporter$10 = () => import("./settings-CJs1gwYq.mjs");
var Route$11 = createFileRoute("/settings")({ component: lazyRouteComponent($$splitComponentImporter$10, "component") });
var DAILY = ["https://database.clamav.net/daily.cvd", "https://packages.microsoft.com/clamav/daily.cvd"];
async function pull(url) {
	const response = await fetch(url, {
		headers: { "user-agent": url.includes("database.clamav.net") ? "ClamAV/1.4.1" : "Kanaf/1.0" },
		signal: AbortSignal.timeout(12e4)
	});
	if (!response.ok) throw new Error(`${response.status} ${url}`);
	return new Uint8Array(await response.arrayBuffer());
}
async function pullText(url) {
	const bytes = await pull(url);
	return new TextDecoder().decode(bytes);
}
function text(body, status = 200) {
	return new Response(body, {
		status,
		headers: {
			"content-type": "text/plain; charset=utf-8",
			"cache-control": "no-store"
		}
	});
}
async function refreshPart(part) {
	try {
		if (part === "urlhaus") {
			const raw = await pullText("https://urlhaus.abuse.ch/downloads/text/");
			const lines = [];
			for (const line of raw.split("\n")) {
				const norm = normalizeUrl(line);
				if (norm) lines.push(norm.href);
			}
			return text(lines.join("\n"));
		}
		if (part === "malwarebazaar") {
			const [sha, md5] = await Promise.all([pullText("https://bazaar.abuse.ch/export/txt/sha256/recent/"), pullText("https://bazaar.abuse.ch/export/txt/md5/recent/")]);
			const rows = [];
			for (const line of sha.split("\n")) {
				const hash = line.trim().toLowerCase();
				if (/^[0-9a-f]{64}$/.test(hash)) rows.push(`sha256\t${hash}\t*\tmalwarebazaar\tMalwareBazaar-recent`);
			}
			for (const line of md5.split("\n")) {
				const hash = line.trim().toLowerCase();
				if (/^[0-9a-f]{32}$/.test(hash)) rows.push(`md5\t${hash}\t*\tmalwarebazaar\tMalwareBazaar-recent`);
			}
			return text(rows.join("\n"));
		}
		if (part === "cscb") {
			const lines = (await pullText("https://bazaar.abuse.ch/export/csv/cscb/")).split("\n").filter((line) => line && !line.startsWith("#") && !line.startsWith("\"time"));
			const rows = [];
			for (const line of lines) {
				const cols = line.split(",");
				const thumb = (cols[2] || "").replaceAll("\"", "").trim().toLowerCase();
				const reason = (cols[8] || "CSCB").replaceAll("\"", "").trim();
				if (/^[0-9a-f]{64}$/.test(thumb)) rows.push(`${thumb}\t${reason}`);
			}
			return text(rows.join("\n"));
		}
		if (part === "clamav-daily") {
			let last = "unavailable";
			for (const url of DAILY) try {
				return text((await parseCvd(await pull(url))).records.map((record) => `${record.kind}\t${record.hash}\t${record.size ?? "*"}\tclamav-daily\t${record.name.replaceAll("	", " ")}`).join("\n"));
			} catch (error) {
				last = error instanceof Error ? error.message : "cvd";
			}
			return text(last, 502);
		}
		if (part === "threatfox") return text(threatFoxToFeed(await pullText("https://threatfox.abuse.ch/export/csv/recent/")));
		if (part === "feodo") return text(ipsToFeed(await pullText("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")));
		if (part === "openphish") return text(urlsToFeed(await pullText("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt")));
		if (part === "et-open") return text(ipsToFeed(await pullText("https://rules.emergingthreats.net/blockrules/compromised-ips.txt")));
		return text("unknown source", 404);
	} catch (error) {
		return text(error instanceof Error ? error.message : "refresh failed", 502);
	}
}
var Route$10 = createFileRoute("/api/signatures")({ server: { handlers: { GET: ({ request }) => {
	return refreshPart(new URL(request.url).searchParams.get("part") ?? "");
} } } });
var $$splitComponentImporter$9 = () => import("./decision._id-WbkQcoYZ.mjs");
var Route$9 = createFileRoute("/decision/$id")({ component: lazyRouteComponent($$splitComponentImporter$9, "component") });
var $$splitComponentImporter$8 = () => import("./settings.index-DReHpHzd.mjs");
var Route$8 = createFileRoute("/settings/")({ component: lazyRouteComponent($$splitComponentImporter$8, "component") });
var $$splitComponentImporter$7 = () => import("./settings.clean-B0xrGWDt.mjs");
var Route$7 = createFileRoute("/settings/clean")({ component: lazyRouteComponent($$splitComponentImporter$7, "component") });
var $$splitComponentImporter$6 = () => import("./settings.device-CgDcTtJE.mjs");
var Route$6 = createFileRoute("/settings/device")({ component: lazyRouteComponent($$splitComponentImporter$6, "component") });
var $$splitComponentImporter$5 = () => import("./settings.folders-Dzk2ilsY.mjs");
var Route$5 = createFileRoute("/settings/folders")({ component: lazyRouteComponent($$splitComponentImporter$5, "component") });
var $$splitComponentImporter$4 = () => import("./settings.log-CkNuhSlF.mjs");
var Route$4 = createFileRoute("/settings/log")({ component: lazyRouteComponent($$splitComponentImporter$4, "component") });
var $$splitComponentImporter$3 = () => import("./settings.network-lANJgjF6.mjs");
var Route$3 = createFileRoute("/settings/network")({ component: lazyRouteComponent($$splitComponentImporter$3, "component") });
var $$splitComponentImporter$2 = () => import("./settings.numbers-DchERA8M.mjs");
var Route$2 = createFileRoute("/settings/numbers")({ component: lazyRouteComponent($$splitComponentImporter$2, "component") });
var $$splitComponentImporter$1 = () => import("./settings.schedule-BOMyDDU0.mjs");
var Route$1 = createFileRoute("/settings/schedule")({ component: lazyRouteComponent($$splitComponentImporter$1, "component") });
var $$splitComponentImporter = () => import("./settings.sources-D3sDlmhd.mjs");
var Route = createFileRoute("/settings/sources")({ component: lazyRouteComponent($$splitComponentImporter, "component") });
var IndexRoute = Route$22.update({
	id: "/",
	path: "/",
	getParentRoute: () => Route$23
});
var AdvisorRoute = Route$21.update({
	id: "/advisor",
	path: "/advisor",
	getParentRoute: () => Route$23
});
var BehaviorRoute = Route$20.update({
	id: "/behavior",
	path: "/behavior",
	getParentRoute: () => Route$23
});
var CheckedRoute = Route$19.update({
	id: "/checked",
	path: "/checked",
	getParentRoute: () => Route$23
});
var LinkRoute = Route$18.update({
	id: "/link",
	path: "/link",
	getParentRoute: () => Route$23
});
var MessagesRoute = Route$17.update({
	id: "/messages",
	path: "/messages",
	getParentRoute: () => Route$23
});
var PhishRoute = Route$16.update({
	id: "/phish",
	path: "/phish",
	getParentRoute: () => Route$23
});
var PrivacyRoute = Route$15.update({
	id: "/privacy",
	path: "/privacy",
	getParentRoute: () => Route$23
});
var QrRoute = Route$14.update({
	id: "/qr",
	path: "/qr",
	getParentRoute: () => Route$23
});
var QuarantineRoute = Route$13.update({
	id: "/quarantine",
	path: "/quarantine",
	getParentRoute: () => Route$23
});
var ResultsRoute = Route$12.update({
	id: "/results",
	path: "/results",
	getParentRoute: () => Route$23
});
var SettingsRoute = Route$11.update({
	id: "/settings",
	path: "/settings",
	getParentRoute: () => Route$23
});
var ApiSignaturesRoute = Route$10.update({
	id: "/api/signatures",
	path: "/api/signatures",
	getParentRoute: () => Route$23
});
var DecisionIdRoute = Route$9.update({
	id: "/decision/$id",
	path: "/decision/$id",
	getParentRoute: () => Route$23
});
var SettingsIndexRoute = Route$8.update({
	id: "/",
	path: "/",
	getParentRoute: () => SettingsRoute
});
var SettingsRouteChildren = {
	SettingsCleanRoute: Route$7.update({
		id: "/clean",
		path: "/clean",
		getParentRoute: () => SettingsRoute
	}),
	SettingsDeviceRoute: Route$6.update({
		id: "/device",
		path: "/device",
		getParentRoute: () => SettingsRoute
	}),
	SettingsFoldersRoute: Route$5.update({
		id: "/folders",
		path: "/folders",
		getParentRoute: () => SettingsRoute
	}),
	SettingsLogRoute: Route$4.update({
		id: "/log",
		path: "/log",
		getParentRoute: () => SettingsRoute
	}),
	SettingsNetworkRoute: Route$3.update({
		id: "/network",
		path: "/network",
		getParentRoute: () => SettingsRoute
	}),
	SettingsNumbersRoute: Route$2.update({
		id: "/numbers",
		path: "/numbers",
		getParentRoute: () => SettingsRoute
	}),
	SettingsScheduleRoute: Route$1.update({
		id: "/schedule",
		path: "/schedule",
		getParentRoute: () => SettingsRoute
	}),
	SettingsSourcesRoute: Route.update({
		id: "/sources",
		path: "/sources",
		getParentRoute: () => SettingsRoute
	}),
	SettingsIndexRoute
};
var rootRouteChildren = {
	IndexRoute,
	AdvisorRoute,
	BehaviorRoute,
	CheckedRoute,
	LinkRoute,
	MessagesRoute,
	PhishRoute,
	PrivacyRoute,
	QrRoute,
	QuarantineRoute,
	ResultsRoute,
	SettingsRoute: SettingsRoute._addFileChildren(SettingsRouteChildren),
	ApiSignaturesRoute,
	DecisionIdRoute
};
var routeTree = Route$23._addFileChildren(rootRouteChildren)._addFileTypes();
var router_exports = /* @__PURE__ */ __exportAll({ getRouter: () => getRouter });
function getRouter() {
	return createRouter({
		routeTree,
		rewrite: previewPathRewrite(),
		defaultErrorComponent: AppErrorComponent
	});
}
//#endregion
export { revokeAllow as A, watchFolder as B, purgeVault as C, rememberUrl as D, refreshSources as E, scanDevice as F, normalizePhone as G, extractUrls as H, scanInbox as I, formatCount as J, adviceLabel as K, scanLink as L, saveDecisions as M, saveSettings as N, removeFolder as O, scanBehavior as P, setRealtime as R, openDeviceSettings as S, readClipboard as T, normalizeUrl as U, useKanaf as V, analyzePhones as W, scanSummary as X, resultsLabel as Y, useI18n as Z, deleteFinding as _, Route$18 as a, metered as b, Frame as c, TopBar as d, allowFinding as f, chooseFolder as g, chooseFiles as h, Route$17 as i, runEicar as j, restoreVault as k, HomeBar as l, cancelScan as m, Route$9 as n, Bidi as o, askCloud as p, behaviorResult as q, Route$16 as r, Confirm as s, router_exports as t, Notice as u, inspectMessage as v, quarantineFinding as w, networkKind as x, keepMessageFinding as y, tryRedirect as z };
