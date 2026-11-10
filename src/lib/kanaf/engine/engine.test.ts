import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { test } from "node:test";
import { eicarBytes } from "./eicar.ts";
import { md5Hex } from "./md5.ts";
import { sha256Hex } from "./sha256.ts";
import { verifyClamAvDsig, parseCvdHeader, CvdError } from "./cvd.ts";
import { emptyDb, lookupHash, mergeRecord, parseHashTsv } from "./signatures.ts";
import { inspectBytes, DEEP_LIMITS } from "./scan.ts";
import { readZip, ZipLimitError } from "./zip.ts";
import { analyzePhones } from "./phone.ts";
import { analyzeMessage, analyzeUrl, normalizeUrl } from "./url.ts";
import { scoreBehavior } from "./behavior.ts";
import { threatFoxToFeed, ipsToFeed, applyFeed } from "./feeds.ts";

const CVD_MD5 = "0b8b78f9de50bda563753ba2d6d5ca34";
const CVD_DSIG =
  "D2rxYlpn4WyxaNIWN2+9UqRC8wGLInHtJ6M9mDvkm5UEaCTudy8q0Hy7QF3H6uYKDKHsdMYWbQym6ACIIRbGxGSkZ3gidVp4fDx57qkPke4TQRhdKKKySOmZM6eZ/l/wTiCfDl1NDjXKyyZFoiKHjZCl5mkeHEI8H1z3FYcPQvd";

test("md5 and sha256 match node crypto, including chunked updates", () => {
  const samples = [new Uint8Array(), new TextEncoder().encode("abc"), eicarBytes(), cryptoRandom(100_000)];
  for (const sample of samples) {
    assert.equal(md5Hex(sample), createHash("md5").update(sample).digest("hex"));
    assert.equal(sha256Hex(sample), createHash("sha256").update(sample).digest("hex"));
  }
  assert.equal(eicarBytes().length, 68);
});

test("ClamAV legacy CVD signature accepts the published daily digest and rejects tampering", () => {
  assert.equal(verifyClamAvDsig(CVD_MD5, CVD_DSIG), true);
  assert.equal(verifyClamAvDsig("0".repeat(32), CVD_DSIG), false);
  assert.equal(verifyClamAvDsig(CVD_MD5, CVD_DSIG.slice(0, -1) + "a"), false);
  assert.throws(() => parseCvdHeader(new Uint8Array([1, 2, 3, 4])), CvdError);
});

test("hash index uses size as a secondary key and merges sources", () => {
  const db = emptyDb();
  parseHashTsv("md5\t44d88612fea8a8f36de82e1278abb02f\t68\tclamav-daily\tEicar-Test-Signature\n", db);
  mergeRecord(db, "sha256", "ab".repeat(32), null, "malwarebazaar", "MalwareBazaar-recent");
  assert.ok(lookupHash(db, "md5", "44d88612fea8a8f36de82e1278abb02f", 68));
  assert.equal(lookupHash(db, "md5", "44d88612fea8a8f36de82e1278abb02f", 67), null);
  assert.ok(lookupHash(db, "sha256", "ab".repeat(32), 10));
});

test("EICAR is detected end to end and an allow-listed hash is skipped", async () => {
  const db = emptyDb();
  const bytes = eicarBytes();
  const sha = sha256Hex(bytes);
  mergeRecord(db, "sha256", sha, 68, "clamav-daily", "Eicar-Test-Signature");
  const found = await inspectBytes({ name: "eicar.com", path: "eicar.com", bytes, db, allow: new Set() });
  assert.equal(found.length, 1);
  assert.equal(found[0].reasonId, "eicar");
  assert.equal(found[0].verdict, "malicious");
  const allowed = await inspectBytes({
    name: "eicar.com",
    path: "eicar.com",
    bytes,
    db,
    allow: new Set([sha]),
  });
  assert.equal(allowed.length, 0);
});

test("archive inspection finds a nested EICAR and stops zip bombs and excess depth", async () => {
  const db = emptyDb();
  const eicar = eicarBytes();
  mergeRecord(db, "md5", md5Hex(eicar), 68, "clamav-daily", "Eicar-Test-Signature");
  const inner = makeZip([{ name: "eicar.com", data: eicar }]);
  const outer = makeZip([{ name: "nested.zip", data: inner }]);
  const found = await inspectBytes({ name: "outer.zip", path: "outer.zip", bytes: outer, db, allow: new Set() });
  assert.ok(found.some((item) => item.reasonId === "eicar"));

  const bomb = makeZip([{ name: "zeros.bin", data: new Uint8Array(8 * 1024 * 1024) }]);
  await assert.rejects(() => readZip(bomb, { ...DEEP_LIMITS, ratioFloor: 1024, maxRatio: 20 }), ZipLimitError);

  let nested = makeZip([{ name: "eicar.com", data: eicar }]);
  for (let i = 0; i < 4; i++) nested = makeZip([{ name: `level${i}.zip`, data: nested }]);
  const deep = await inspectBytes({
    name: "deep.zip",
    path: "deep.zip",
    bytes: nested,
    db,
    allow: new Set(),
    limits: DEEP_LIMITS,
  });
  assert.ok(deep.some((item) => item.reasonId === "archive-depth"));
});

test("url and message analysis stay local and respect trusted senders", () => {
  const hosts = new Set(["evil.example"]);
  const urls = new Set(["http://evil.example/payload"]);
  const listed = analyzeUrl("http://evil.example/payload", { hosts, urls });
  assert.equal(listed?.verdict, "malicious");
  const look = analyzeUrl("http://o0redoo.om/login", { hosts, urls });
  assert.equal(look?.verdict, "suspicious");
  assert.ok(look?.reasons.includes("lookalike"));
  assert.equal(look?.hint, "ooredoo.om");
  const norm = normalizeUrl("HTTPS://Example.COM:443/a/");
  assert.equal(norm?.href, "https://example.com/a");

  const trusted = [{ names: ["Ooredoo"], domains: ["ooredoo.om"] }];
  const safe = analyzeMessage({
    sender: "Ooredoo",
    text: "Your bill is ready https://my.ooredoo.om/bill",
    trusted,
    db: { hosts, urls },
  });
  assert.equal(safe.verdict, "clean");
  const spoof = analyzeMessage({
    sender: "Ooredoo",
    text: "Pay now http://evil.example/payload",
    trusted,
    db: { hosts, urls },
  });
  assert.equal(spoof.verdict, "malicious");
  assert.ok(spoof.reasons.includes("trusted-sender-off-domain") || spoof.verdict === "malicious");
  const plain = analyzeMessage({ sender: "Ali", text: "أراك غدًا في المقهى", trusted, db: { hosts, urls } });
  assert.equal(plain.verdict, "clean");
  const short = analyzeUrl("https://bit.ly/bill", { hosts, urls });
  assert.equal(short?.verdict, "clean");
  const pub = analyzeUrl("http://8.8.8.8/login", { hosts, urls });
  assert.equal(pub?.verdict, "suspicious");
  const lan = analyzeUrl("http://192.168.1.1/admin", { hosts, urls });
  assert.equal(lan?.verdict, "clean");
  const trick = analyzeUrl("https://paypal.com@hidden.example/login", { hosts, urls });
  assert.equal(trick?.verdict, "suspicious");
  assert.ok(trick?.reasons.includes("userinfo"));
  assert.equal(trick?.host, "hidden.example");
});

test("threatfox feed keeps high-confidence hashes and drops weak rows", () => {
  const raw = [
    '# comment',
    '"2026-10-19 06:41:13", "1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256_hash", "payload", "win.test", "None", "TestFamily", "", "100", "False", "None", "tag", "0", "lab"',
    '"2026-10-19 06:40:48", "2", "https://evil.example/gate", "url", "botnet_cc", "win.vidar", "None", "Vidar", "", "90", "True", "None", "vidar", "0", "lab"',
    '"2026-10-19 06:37:27", "3", "maybe.example", "domain", "payload_delivery", "php.test", "None", "Weak", "", "50", "True", "None", "tag", "0", "lab"',
  ].join("\n");
  const feed = threatFoxToFeed(raw);
  assert.match(feed, /sha256\ta{64}\t\*\tthreatfox\tTestFamily/);
  assert.match(feed, /U https:\/\/evil\.example\/gate/);
  assert.doesNotMatch(feed, /maybe\.example/);
  const ips = ipsToFeed("# c\n1.2.3.4\nnot-an-ip\n");
  assert.equal(ips, "H 1.2.3.4");
  const db = emptyDb();
  applyFeed(`${feed}\n${ips}`, db);
  assert.equal(lookupHash(db, "sha256", "a".repeat(64), 10)?.source, "threatfox");
  assert.ok(db.hosts.has("1.2.3.4"));
});

test("behavior model stays quiet for a store app and a normal package, and flags overlay with accessibility", () => {
  const quiet = scoreBehavior({
    path: "apps/com.example.notes",
    strings: ["android.permission.INTERNET", "android.intent.category.LAUNCHER"],
  });
  assert.equal(quiet.band, "clean");
  const youtube = scoreBehavior({
    path: "apps/com.google.android.youtube",
    strings: [
      "android.permission.INTERNET",
      "android.permission.REQUEST_INSTALL_PACKAGES",
      "android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.BIND_ACCESSIBILITY_SERVICE",
    ],
    dex: { dynamicLoad: true, packer: null, shortNameRatio: 0.9, stringsSeen: 80000, smsApi: false, accessApi: false, hideIcon: false, adminApi: false },
  });
  assert.equal(youtube.band, "clean");
  assert.equal(youtube.ratio, 0);
  const banker = scoreBehavior({
    path: "apps/com.example.overlay",
    strings: ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
  });
  assert.equal(banker.band, "suspicious");
  assert.ok(banker.ratio >= 1);
  assert.ok(banker.reasons.includes("overlay-accessibility"));
  const stealer = scoreBehavior({
    path: "apps/com.example.codes",
    strings: ["android.intent.category.LAUNCHER"],
    dex: { dynamicLoad: false, packer: null, shortNameRatio: 0, stringsSeen: 20, smsApi: true, accessApi: true, hideIcon: true, adminApi: false },
  });
  assert.equal(stealer.band, "suspicious");
  assert.ok(stealer.reasons.includes("dex-sms-access"));
  assert.ok(stealer.reasons.includes("hide-icon"));
});

function cryptoRandom(size: number): Uint8Array {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) out[i] = (i * 17 + 3) & 0xff;
  return out;
}

test("documents and pictures are judged by structure, and a bank name alone is clean", async () => {
  const db = emptyDb();
  const doc = makeZip([{ name: "word/vbaProject.bin", data: new Uint8Array([1, 2, 3, 4]) }]);
  const macro = await inspectBytes({ name: "invoice.docm", path: "invoice.docm", bytes: doc, db, allow: new Set() });
  assert.ok(macro.some((item) => item.reasonId === "macro"));
  const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xd9]);
  assert.equal((await inspectBytes({ name: "a.jpg", path: "a.jpg", bytes: jpeg, db, allow: new Set() })).length, 0);
  const trailer = new Uint8Array(16);
  trailer[0] = 0x4d;
  trailer[1] = 0x5a;
  const glued = await inspectBytes({ name: "a.jpg", path: "a.jpg", bytes: concat([jpeg, trailer]), db, allow: new Set() });
  assert.ok(glued.some((item) => item.reasonId === "polyglot"));
  const empty = { hosts: new Set<string>(), urls: new Set<string>() };
  const talk = analyzeMessage({ sender: "Ali", text: "حوّل المبلغ إلى بنك مسقط غدًا", trusted: [], db: empty });
  assert.equal(talk.verdict, "clean");
  const planted = analyzeUrl("https://paypal-secure.example/login", empty);
  assert.equal(planted?.verdict, "suspicious");
  assert.ok(planted?.reasons.includes("brand-host"));
  assert.equal(analyzeUrl("https://bankmuscat.com/login", empty)?.verdict, "clean");
  const plain = analyzePhones("91234567");
  assert.equal(plain[0]?.e164, "+96891234567");
  assert.equal(plain[0]?.verdict, "clean");
  assert.ok(analyzePhones("+882331234567")[0]?.reasons.includes("premium-rate"));
  const lure = analyzeMessage({ sender: "x", text: "بنك مسقط: حسابك موقوف. اتصل 91234567", trusted: [], db: empty });
  assert.equal(lure.verdict, "suspicious");
  assert.ok(lure.reasons.includes("callback-lure"));
  const wording = analyzeMessage({ sender: "x", text: "سيتم إغلاق الخدمة خلال ساعة. راجع الفرع", trusted: [], db: empty });
  assert.equal(wording.verdict, "suspicious");
  assert.ok(wording.reasons.includes("lure-model"));
  assert.match(wording.clause, /إغلاق/);
  const near = analyzeUrl("https://bankmuscaat.com/login", empty);
  assert.equal(near?.hint, "bankmuscat.com");
  const arabicHost = new URL("http://نماه.com").hostname;
  const arabic = analyzeUrl(`http://${arabicHost}/`, empty);
  assert.equal(arabic?.hint, "نماء");
  const code = analyzeMessage({ sender: "x", text: "رمز التحقق 482193 من بنك مسقط", trusted: [], db: empty });
  assert.equal(code.verdict, "clean");
  assert.equal(analyzePhones("اتصل 91234567")[0]?.verdict, "clean");
  const confirmed = analyzePhones("بنك مسقط: حسابك موقوف. اتصل 91234567", ["+96891234567"]);
  assert.equal(confirmed[0]?.verdict, "clean");
});

function makeZip(files: { name: string; data: Uint8Array }[]): Uint8Array {
  const locals: Uint8Array[] = [];
  const centrals: Uint8Array[] = [];
  let offset = 0;
  for (const file of files) {
    const name = new TextEncoder().encode(file.name);
    const compressed = deflateRawSync(file.data);
    const useStore = compressed.length >= file.data.length;
    const payload = useStore ? file.data : compressed;
    const method = useStore ? 0 : 8;
    const local = new Uint8Array(30 + name.length + payload.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(8, method, true);
    lv.setUint32(18, payload.length, true);
    lv.setUint32(22, file.data.length, true);
    lv.setUint16(26, name.length, true);
    local.set(name, 30);
    local.set(payload, 30 + name.length);
    locals.push(local);
    const central = new Uint8Array(46 + name.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(10, method, true);
    cv.setUint32(20, payload.length, true);
    cv.setUint32(24, file.data.length, true);
    cv.setUint16(28, name.length, true);
    cv.setUint32(42, offset, true);
    central.set(name, 46);
    centrals.push(central);
    offset += local.length;
  }
  const centralBlob = concat(centrals);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, files.length, true);
  ev.setUint16(10, files.length, true);
  ev.setUint32(12, centralBlob.length, true);
  ev.setUint32(16, offset, true);
  return concat([...locals, centralBlob, eocd]);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(size);
  let o = 0;
  for (const part of parts) {
    out.set(part, o);
    o += part.length;
  }
  return out;
}
