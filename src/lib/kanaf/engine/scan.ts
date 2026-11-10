import { axmlStrings, certificatesFromPkcs, dexSignals, type DexSignals } from "./apk.ts";
import { isStorePackage, scoreBehavior } from "./behavior.ts";
import { lookupHash, type SignatureDb } from "./signatures.ts";
import { classify, isRar, looksLikeZip, looseRisks, officeRisks, shouldOpenOfficeEntry } from "./content.ts";
import { isArchiveName, readZip, type ZipLimits, DEFAULT_ZIP_LIMITS } from "./zip.ts";
import { Md5 } from "./md5.ts";
import { Sha256 } from "./sha256.ts";

export type FileVerdict = "malicious" | "suspicious";

export type FileEvidence = {
  name: string;
  path: string;
  size: number;
  md5: string;
  sha256: string;
  verdict: FileVerdict;
  reasonId: string;
  detail: string;
  permissions: string[];
  signatureName?: string;
  sourceId?: string;
};

function apkPart(name: string): boolean {
  return (
    /(^|\/)AndroidManifest\.xml$/i.test(name) ||
    /(^|\/)classes\d*\.dex$/i.test(name) ||
    /^META-INF\/.+\.(RSA|DSA|EC)$/i.test(name)
  );
}

export type ScanLimits = ZipLimits & { maxDepth: number };

export const DEEP_LIMITS: ScanLimits = { ...DEFAULT_ZIP_LIMITS, maxDepth: 3 };
export const QUICK_LIMITS: ScanLimits = {
  ...DEFAULT_ZIP_LIMITS,
  maxDepth: 1,
  maxUncompressed: 32 * 1024 * 1024,
  maxSingle: 16 * 1024 * 1024,
};

export async function hashBuffer(bytes: Uint8Array): Promise<{ md5: string; sha256: string }> {
  const md5 = new Md5();
  const sha = new Sha256();
  const step = 64 * 1024;
  for (let i = 0; i < bytes.length; i += step) {
    const slice = bytes.subarray(i, i + step);
    md5.update(slice);
    sha.update(slice);
  }
  return { md5: md5.hex(), sha256: sha.hex() };
}

export async function inspectBytes(input: {
  name: string;
  path: string;
  bytes: Uint8Array;
  db: SignatureDb;
  allow: Set<string>;
  limits?: ScanLimits;
  depth?: number;
  markers?: string[];
}): Promise<FileEvidence[]> {
  const limits = input.limits ?? DEEP_LIMITS;
  const depth = input.depth ?? 0;
  const { md5, sha256 } = await hashBuffer(input.bytes);
  if (input.allow.has(sha256) || input.allow.has(md5)) return [];
  const found: FileEvidence[] = [];
  const hashHit =
    lookupHash(input.db, "sha256", sha256, input.bytes.length) ??
    lookupHash(input.db, "md5", md5, input.bytes.length);
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
      sourceId: hashHit.source,
    });
  }

  if (input.markers?.length) {
    const judged = scoreBehavior({ path: input.path, strings: input.markers });
    if (judged.band === "suspicious" && !found.some((item) => item.verdict === "malicious" && item.path === input.path)) {
      found.push({
        ...base(input, md5, sha256, "suspicious", "heuristic", judged.reasons.join(",")),
        permissions: judged.permissions,
      });
    }
  }

  if (isArchiveName(input.name) || (looksLikeZip(input.bytes) && !isRar(input.bytes) && classify(input.name, input.bytes) !== "image")) {
    if (depth >= limits.maxDepth) {
      found.push(base(input, md5, sha256, "suspicious", "archive-depth", String(limits.maxDepth)));
      return dedupe(found);
    }
    const apk = /\.(apk|xapk|apks)$/i.test(input.name);
    const office = /\.(docx|xlsx|xlsm|xltm|docm|pptx|pptm)$/i.test(input.name);
    try {
      const entries = await readZip(
        input.bytes,
        apk
          ? { ...limits, maxEntries: 50000, maxSingle: 80 * 1024 * 1024, maxUncompressed: 240 * 1024 * 1024 }
          : limits,
        apk ? (name) => apkPart(name) || /\.(zip|jar)$/i.test(name) : undefined,
      );
      const manifest = entries.find((e) => e.name === "AndroidManifest.xml" || e.name.endsWith("/AndroidManifest.xml"));
      const dex = entries.filter((e) => /(^|\/)classes\d*\.dex$/i.test(e.name));
      const certBlobs = entries.filter((e) => /^META-INF\/.+\.(RSA|DSA|EC)$/i.test(e.name));
      if (manifest || dex.length || apk) {
        const strings = [...(manifest ? axmlStrings(manifest.bytes) : []), ...(input.markers ?? [])];
        const dexInfo = dex.reduce<DexSignals>(
          (acc, entry) => {
            const next = dexSignals(entry.bytes);
            return {
              dynamicLoad: acc.dynamicLoad || next.dynamicLoad,
              packer: acc.packer ?? next.packer,
              shortNameRatio: Math.max(acc.shortNameRatio, next.shortNameRatio),
              stringsSeen: acc.stringsSeen + next.stringsSeen,
              smsApi: acc.smsApi || next.smsApi,
              accessApi: acc.accessApi || next.accessApi,
              hideIcon: acc.hideIcon || next.hideIcon,
              adminApi: acc.adminApi || next.adminApi,
            };
          },
          { dynamicLoad: false, packer: null, shortNameRatio: 0, stringsSeen: 0, smsApi: false, accessApi: false, hideIcon: false, adminApi: false },
        );
        let debug = false;
        for (const cert of certBlobs) {
          for (const hit of certificatesFromPkcs(cert.bytes)) {
            debug = debug || hit.debug;
            const listed = input.db.certs.get(hit.sha256);
            if (listed) {
              found.push({
                ...base(input, md5, sha256, "malicious", "bad-cert", listed),
                signatureName: listed,
                sourceId: "cscb",
              });
            }
          }
        }
        const judged = scoreBehavior({ path: input.path, strings, dex: dexInfo, debugCert: debug });
        if (
          judged.band === "suspicious" &&
          !isStorePackage(input.path) &&
          !found.some((item) => item.verdict === "malicious" && item.path === input.path)
        ) {
          found.push({
            ...base(input, md5, sha256, "suspicious", "heuristic", judged.reasons.join(",")),
            permissions: judged.permissions,
          });
        }
      }
      if (office) {
        for (const risk of officeRisks(entries, input.db)) {
          found.push(base(input, md5, sha256, "suspicious", risk.reasonId, risk.detail));
        }
      }
      for (const entry of entries) {
        if (apk && !isArchiveName(entry.name)) continue;
        if (office && !shouldOpenOfficeEntry(entry.name)) continue;
        if (entry.uncompressedSize > 8 * 1024 * 1024 && apk) continue;
        const inner = await inspectBytes({
          name: entry.name.split("/").pop() || entry.name,
          path: `${input.path}/${entry.name}`,
          bytes: entry.bytes,
          db: input.db,
          allow: input.allow,
          limits,
          depth: depth + 1,
        });
        found.push(...inner.filter((item) => item.verdict === "malicious" || !apk));
      }
    } catch {
      /* An unreadable or oversized archive is not a detection. */
    }
  }
  if (!found.some((item) => item.verdict === "malicious")) {
    for (const risk of looseRisks(input.name, input.bytes)) {
      found.push(base(input, md5, sha256, "suspicious", risk.reasonId, risk.detail));
    }
  }
  return dedupe(found);
}

function base(
  input: { name: string; path: string; bytes: Uint8Array },
  md5: string,
  sha256: string,
  verdict: FileVerdict,
  reasonId: string,
  detail: string,
): FileEvidence {
  return {
    name: input.name,
    path: input.path,
    size: input.bytes.length,
    md5,
    sha256,
    verdict,
    reasonId,
    detail,
    permissions: [],
  };
}

function dedupe(items: FileEvidence[]): FileEvidence[] {
  const seen = new Set<string>();
  const out: FileEvidence[] = [];
  for (const item of items) {
    const key = `${item.path}|${item.reasonId}|${item.sha256}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}
