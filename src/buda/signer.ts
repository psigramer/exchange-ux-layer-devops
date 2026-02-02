// src/buda/signer.ts
import crypto from "node:crypto";

export type BudaSignInput = {
  method: string;           // "GET", "POST", etc.
  pathWithQuery: string;    // "/api/v2/balances" (+ "?x=y" si aplica)
  nonce: string;            // monotonic integer string
  body?: string | null;     // raw body (JSON string) if any, else null/undefined/empty
  apiSecret: string;        // BUDA_API_SECRET
};

export function base64Body(rawBody: string): string {
  if (!rawBody) return "";
  return Buffer.from(rawBody, "utf8").toString("base64");
}

/**
 * Canonical string rules (validated vs prod):
 * components = [METHOD, path_with_query]
 * if body exists (non-empty): push base64(body)
 * push nonce
 * canonical = components.join(" ")
 */
export function makeBudaCanonicalString(args: Omit<BudaSignInput, "apiSecret">): string {
  const method = args.method.toUpperCase();
  const components: string[] = [method, args.pathWithQuery];

  const rawBody = args.body ?? "";
  if (rawBody.length > 0) {
    components.push(base64Body(rawBody));
  }

  components.push(args.nonce);
  return components.join(" ");
}

export function hmacSha384Hex(secret: string, message: string): string {
  return crypto.createHmac("sha384", secret).update(message, "utf8").digest("hex");
}

export function signBuda(args: BudaSignInput): { canonical: string; signature: string } {
  const canonical = makeBudaCanonicalString({
    method: args.method,
    pathWithQuery: args.pathWithQuery,
    nonce: args.nonce,
    body: args.body ?? "",
  });

  const signature = hmacSha384Hex(args.apiSecret, canonical);
  return { canonical, signature };
}
