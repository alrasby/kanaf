import type { DexSignals } from "./apk.ts";

/**
 * Static indicators for an application package. A hit is "suspicious", never
 * "malicious". Ordinary store apps use R8, DexClassLoader, and a large APK;
 * those are not signals. Only combinations used by overlay bankers and packers
 * reach the threshold.
 */
export const HEURISTIC_THRESHOLD = 100;

export const HEURISTIC_WEIGHTS = {
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
  smsOverlay: 100,
} as const;

export type HeuristicHit = {
  score: number;
  reasons: string[];
  permissions: string[];
};

const PERM = {
  overlay: "android.permission.SYSTEM_ALERT_WINDOW",
  accessibility: "android.permission.BIND_ACCESSIBILITY_SERVICE",
  sms: "android.permission.RECEIVE_SMS",
  readSms: "android.permission.READ_SMS",
  internet: "android.permission.INTERNET",
  admin: "android.permission.BIND_DEVICE_ADMIN",
  install: "android.permission.REQUEST_INSTALL_PACKAGES",
};

export function scoreApplication(input: {
  strings: string[];
  dex: DexSignals;
  debugCert: boolean;
}): HeuristicHit {
  const set = new Set(input.strings);
  const permissions = [...set].filter((s) => s.startsWith("android.permission.")).sort();
  const reasons: string[] = [];
  let score = 0;
  const has = (name: string) => set.has(name) || permissions.includes(name);
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
  return { score, reasons, permissions };
}
