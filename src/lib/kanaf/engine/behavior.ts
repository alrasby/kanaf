import type { DexSignals } from "./apk.ts";
import { HEURISTIC_THRESHOLD, scoreApplication, type HeuristicHit } from "./heuristics.ts";

/** Local linear behavior model. Revision bumps when the weights change. */
export const BEHAVIOR_REV = 4;

const STORE_PREFIXES = [
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
  "com.motorola.",
];

export function isStorePackage(path: string): boolean {
  const match = path.match(/(?:^|\/)apps\/([a-zA-Z][\w.]*)/);
  const name = match?.[1]?.toLowerCase();
  if (!name) return false;
  return STORE_PREFIXES.some((prefix) => name === prefix || name.startsWith(prefix));
}

export type BehaviorBand = "clean" | "suspicious";

export type BehaviorHit = HeuristicHit & {
  ratio: number;
  band: BehaviorBand;
};

const EMPTY_DEX: DexSignals = {
  dynamicLoad: false,
  packer: null,
  shortNameRatio: 0,
  stringsSeen: 0,
  smsApi: false,
  accessApi: false,
  hideIcon: false,
  adminApi: false,
};

export function scoreBehavior(input: {
  path: string;
  strings: string[];
  dex?: DexSignals;
  debugCert?: boolean;
}): BehaviorHit {
  if (isStorePackage(input.path)) {
    return { score: 0, ratio: 0, band: "clean", reasons: [], permissions: [] };
  }
  const hit = scoreApplication({
    strings: input.strings,
    dex: input.dex ?? EMPTY_DEX,
    debugCert: input.debugCert ?? false,
  });
  const ratio = Math.min(1, hit.score / HEURISTIC_THRESHOLD);
  return { ...hit, ratio, band: hit.score >= HEURISTIC_THRESHOLD ? "suspicious" : "clean" };
}
