export type PhoneVerdict = "clean" | "suspicious";

export type PhoneFinding = {
  raw: string;
  e164: string;
  verdict: PhoneVerdict;
  reasons: string[];
};

const CALL = /اتصل|كلمني|كلّمني|واتساب|واتس|whatsapp|wa\.me|call me|call now|تواصل/i;
const LURE = /رمز|otp|كلمة السر|كلمة المرور|password|cvv|حسابك|موقوف|تجميد|بطاقة|تحقق من/i;
const BRAND = /بنك|bank|paypal|ooredoo|أوريدو|اوريدو|omantel|عمانتل|واتساب|whatsapp|نماء|nama/i;

/** Pulls phone-like tokens. Six-digit codes and dotted addresses are ignored. */
export function extractPhones(text: string): string[] {
  const matches = text.match(/(?:\+|00)?\d[\d\s()-]{5,18}\d/g) ?? [];
  const out: string[] = [];
  for (const raw of matches) {
    const e164 = normalizePhone(raw);
    if (!e164 || out.includes(e164)) continue;
    out.push(e164);
  }
  return out;
}

export function normalizePhone(raw: string): string | null {
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

export function analyzePhones(text: string, official: string[] = []): PhoneFinding[] {
  const known = new Set(official.map((value) => normalizePhone(value)).filter((value): value is string => Boolean(value)));
  const asks = CALL.test(text) && (LURE.test(text) || BRAND.test(text));
  return extractPhones(text).map((e164) => {
    if (known.has(e164)) return { raw: e164, e164, verdict: "clean" as const, reasons: [] };
    const reasons: string[] = [];
    if (isPremium(e164)) reasons.push("premium-rate");
    else if (asks && e164.startsWith("+") && e164.length >= 11) reasons.push("callback-lure");
    return { raw: e164, e164, verdict: reasons.length ? "suspicious" : "clean", reasons };
  });
}

function isPremium(e164: string): boolean {
  return e164.startsWith("+882") || e164.startsWith("+883") || e164.startsWith("+979");
}
