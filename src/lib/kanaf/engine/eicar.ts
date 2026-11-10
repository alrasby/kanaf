/** Official EICAR standard anti-malware test file. 68 bytes, not a virus. */
export const EICAR_TEXT =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

export function eicarBytes(): Uint8Array {
  return new TextEncoder().encode(EICAR_TEXT);
}
