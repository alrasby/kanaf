//#region node_modules/.nitro/vite/services/ssr/assets/reasons-CVaRkdUl.js
var heuristic = {
	"overlay-accessibility": "overlay",
	"sms-internet": "smsNet",
	"device-admin": "admin",
	"no-launcher": "launcher",
	"dynamic-obfuscated": "dynamic",
	"dynamic-load": "dynamic",
	packer: "packer",
	"test-key": "testKey",
	"install-internet": "installNet",
	"dex-sms-access": "dexSms",
	"hide-icon": "hideIcon",
	"dex-admin": "dexAdmin",
	"sms-access": "smsAccess",
	"sms-overlay": "smsOverlay"
};
function reasonLines(t, reasonId, detail) {
	if (reasonId === "eicar") return [{
		text: t.eicarReason,
		detail
	}];
	if (reasonId === "hash-match") return [{
		text: t.hashMatch,
		detail
	}];
	if (reasonId === "bad-cert") return [{
		text: t.badCert,
		detail
	}];
	if (reasonId === "archive-depth") return [{ text: t.archiveDepth }];
	if (reasonId === "zip-corrupt") return [{ text: t.zipCorrupt }];
	if (reasonId.startsWith("zip-")) return [{
		text: t.zipLimit,
		detail
	}];
	if (reasonId === "listed") return [{
		text: t.listed,
		detail
	}];
	if (reasonId === "ip-host") return [{ text: t.ipHost }];
	if (reasonId === "shortener") return [{ text: t.shortener }];
	if (reasonId === "punycode") return [{
		text: t.punycode,
		detail
	}];
	if (reasonId === "lookalike") return [{ text: detail ? `${t.lookalike} ${detail}` : t.lookalike }];
	if (reasonId === "lure-model") return [{ text: detail ? `${t.lureModel} ${detail}` : t.lureModel }];
	if (reasonId === "cloud-lure") return [{ text: detail ? `${t.cloudLure} ${detail}` : t.cloudLure }];
	if (reasonId === "userinfo") return [{
		text: t.userinfo,
		detail
	}];
	if (reasonId === "brand-host") return [{
		text: t.brandHost,
		detail
	}];
	if (reasonId === "premium-rate") return [{
		text: t.phonePremium,
		detail
	}];
	if (reasonId === "callback-lure") return [{
		text: t.phoneLure,
		detail
	}];
	if (reasonId === "macro") return [{ text: t.macro }];
	if (reasonId === "doc-link") return [{
		text: t.docLink,
		detail
	}];
	if (reasonId === "polyglot") return [{ text: t.polyglot }];
	if (reasonId === "pdf-launch") return [{ text: t.pdfLaunch }];
	if (reasonId === "pdf-active") return [{ text: t.pdfActive }];
	if (reasonId === "cert-changed") return [{
		text: t.certChanged,
		detail
	}];
	if (reasonId === "trusted-sender-off-domain") return [{
		text: t.offDomain,
		detail
	}];
	if (reasonId === "heuristic") {
		const lines = String(detail || "").split(",").filter(Boolean).map((code) => ({ text: t[heuristic[code] ?? "heuristic"] }));
		return lines.length ? lines : [{ text: t.heuristic }];
	}
	return [{
		text: t.heuristic,
		detail
	}];
}
//#endregion
export { reasonLines as t };
