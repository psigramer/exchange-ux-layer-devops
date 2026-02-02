// src/buda/nonce.ts
let lastNonce = 0n;

/**
 * Monotonic nonce in microseconds.
 * Ensures monotonicity even if called multiple times in the same millisecond.
 */
export function nextNonceMicros(): string {
  const now = BigInt(Date.now()) * 1000n;
  if (now <= lastNonce) lastNonce = lastNonce + 1n;
  else lastNonce = now;
  return lastNonce.toString();
}
