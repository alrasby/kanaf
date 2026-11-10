/** Local linear model for lure wording. A hit is suspicious, never malicious. */

export type LureHit = { clause: string };

const GROUPS: { id: string; weight: number; pattern: RegExp }[] = [
  { id: "closure", weight: 50, pattern: /اغلاق|إغلاق|ايقاف|إيقاف|موقوف|تجميد|suspend|closed|closure|terminat|disabled|will be stopped/i },
  { id: "account", weight: 20, pattern: /حساب|account|الرصيد|balance/i },
  { id: "brand", weight: 20, pattern: /بنك|bank|paypal|ooredoo|أوريدو|اوريدو|omantel|عمانتل|واتساب|whatsapp|نماء|nama|apple|microsoft|instagram/i },
  { id: "callback", weight: 30, pattern: /عاود الاتصال|اعد الاتصال|أعد الاتصال|يرجى الاتصال|الرجاء الاتصال|اتصل بنا|call back|call us|ring us|dial/i },
  { id: "urgency", weight: 20, pattern: /فورا|فورًا|فوراً|خلال ساعة|مهلة|آخر تنبيه|اخر تنبيه|immediately|urgent|right away|within \d+ hour/i },
  { id: "threat", weight: 35, pattern: /غرامة|بلاغ|قانوني|شرطة|legal action|police|penalty|fine/i },
  { id: "credential", weight: 30, pattern: /كلمة المرور|كلمة السر|الرمز السري|password|one[- ]time|cvv|pin code/i },
];

const THRESHOLD = 70;

export function scoreLure(text: string): LureHit | null {
  let best: { score: number; groups: number; clause: string } | null = null;
  for (const clause of clauses(text)) {
    let score = 0;
    let groups = 0;
    for (const group of GROUPS) {
      if (!group.pattern.test(clause)) continue;
      score += group.weight;
      groups += 1;
    }
    if (groups < 2) continue;
    if (!best || score > best.score) best = { score, groups, clause };
  }
  if (!best || best.score < THRESHOLD) return null;
  const clause = best.clause.replace(/\s+/g, " ").trim().slice(0, 180);
  return clause ? { clause } : null;
}

function clauses(text: string): string[] {
  const parts = text
    .split(/[\n.!?؟]+/)
    .map((part) => part.trim())
    .filter((part) => part.length >= 8);
  return parts.length ? parts : [text.trim()];
}
