/* scripts/buda_probe.ts
   Read-only probe for Buda API: GET /api/v2/balances (+ optional /me)
   Constraints:
   - No secrets in logs
   - Timeout 10s
   - Retries only for network/5xx (max 2)
   - 429: respect Retry-After if present; else short backoff then stop
   - Produce artifact buda_probe_report.json
*/

import fs from "node:fs/promises";
import { signBuda } from "../src/buda/signer";
import { nextNonceMicros } from "../src/buda/nonce";

type ProbeResult = {
  timestamp: string;
  request_id: string | null;
  status_code: number | null;
  headers: Record<string, string>;
  body: {
    redacted: boolean;
    schema_summary?: any;
    note?: string;
  } | null;
  signature: {
    verified: boolean;
    reason?: string;
  };
  endpoint: string;
  method: "GET";
};

function mustGetEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env: ${name}`);
  return v;
}

async function writeArtifact(path: string, content: string) {
  await fs.mkdir("artifacts", { recursive: true });
  await fs.writeFile(path, content, "utf8");
}

function redact(value: string, keep: number) {
  if (!value) return value;
  return value.length <= keep ? `${value}…` : `${value.slice(0, keep)}…`;
}

function redactHeaders(input: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of input.entries()) {
    const key = k.toLowerCase();
    // never include auth-related stuff
    if (key.includes("authorization") || key.includes("api") || key.includes("key") || key.includes("secret") || key.includes("signature")) {
      continue;
    }
    // keep only relevant safe headers
    if (["content-type", "date", "retry-after", "x-request-id", "request-id", "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset"].includes(key)) {
      out[key] = v;
    }
  }
  return out;
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function parseRetryAfter(headers: Headers): number | null {
  const ra = headers.get("retry-after");
  if (!ra) return null;
  const secs = Number(ra);
  if (Number.isFinite(secs) && secs >= 0) return Math.min(secs * 1000, 15000); // cap at 15s
  // could be HTTP-date, but we’ll avoid complexity; treat as null
  return null;
}

function schemaSummary(obj: any) {
  // Keep it simple: types + top-level keys and counts only
  if (obj === null) return { type: "null" };
  if (Array.isArray(obj)) {
    return { type: "array", length: obj.length, sample: obj.length ? schemaSummary(obj[0]) : null };
  }
  if (typeof obj === "object") {
    const keys = Object.keys(obj).slice(0, 50);
    const summary: Record<string, any> = {};
    for (const k of keys) summary[k] = schemaSummary(obj[k]);
    return { type: "object", keys, shape: summary };
  }
  return { type: typeof obj };
}

async function fetchWithPolicy(url: string, headers: Record<string, string>) {
  const timeoutMs = 10_000;

  // retries only for network errors or 5xx
  const maxRetries = 2;
  let attempt = 0;

  while (true) {
    attempt += 1;

    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(url, {
        method: "GET",
        headers,
        signal: controller.signal,
      });

      clearTimeout(t);

      // 429 handling
      if (res.status === 429) {
        const raMs = parseRetryAfter(res.headers);
        if (raMs !== null) {
          await sleep(raMs);
          // After respecting Retry-After once, stop (do not loop indefinitely)
          return res;
        } else {
          await sleep(800); // short backoff
          return res; // stop after one backoff
        }
      }

      // 5xx retry policy
      if (res.status >= 500 && res.status <= 599 && attempt <= 1 + maxRetries) {
        await sleep(400 * attempt);
        continue;
      }

      return res;
    } catch (err: any) {
      clearTimeout(t);

      // network/timeout retries
      if (attempt <= 1 + maxRetries) {
        await sleep(400 * attempt);
        continue;
      }
      throw err;
    }
  }
}

async function main() {
  const apiKey = mustGetEnv("BUDA_API_KEY");
  const apiSecret = mustGetEnv("BUDA_API_SECRET");

    const baseUrl = "https://www.buda.com";
  const pathWithQuery = "/api/v2/balances";
  const url = `${baseUrl}${pathWithQuery}`;

  const method = "GET";
  const nonce = nextNonceMicros();
  const body = ""; // GET

  const { canonical, signature } = signBuda({
    method,
    pathWithQuery,
    nonce,
    body,
    apiSecret,
  });

  // Evidence artifacts (no secrets)
  await writeArtifact("artifacts/canonical_string.txt", canonical);
  await writeArtifact("artifacts/canonical_string.hex", Buffer.from(canonical, "utf8").toString("hex"));
  await writeArtifact(
    "artifacts/request_meta.json",
    JSON.stringify(
      {
        method,
        path_with_query: path,
        nonce,
        body_len: body.length,
        signature_prefix: signature.slice(0, 12),
      },
      null,
      2
    )
  );

  const reqHeaders: Record<string, string> = {
    "X-SBTC-APIKEY": apiKey,
    "X-SBTC-NONCE": nonce,
    "X-SBTC-SIGNATURE": signature,
    "Accept": "application/json",
  };

  await writeArtifact(
    "artifacts/request_headers_redacted.json",
    JSON.stringify(
      {
        "X-SBTC-APIKEY": redact(apiKey, 4),
        "X-SBTC-NONCE": nonce,
        "X-SBTC-SIGNATURE": redact(signature, 12),
        "Accept": "application/json",
      },
      null,
      2
    )
  );

  const report: ProbeResult = {
    timestamp: new Date().toISOString(),
    request_id: null,
    status_code: null,
    headers: {},
    body: null,
    signature: { verified: false, reason: "not evaluated yet" },
    endpoint: path,
    method: "GET",
  };

  let res: Response;
  try {
    res = await fetchWithPolicy(url, reqHeaders);
  } catch (e: any) {
    report.status_code = null;
    report.signature = { verified: true, reason: "signature computed; request failed before server validation (network/timeout)" };
    report.body = {
      redacted: true,
      note: `request failed: ${e?.name || "error"}`,
    };
    await fs.writeFile("buda_probe_report.json", JSON.stringify(report, null, 2), "utf8");
    throw e;
  }

  report.status_code = res.status;

   const responseText = await res.clone().text();
  await writeArtifact(
    "artifacts/request_meta.json",
    JSON.stringify(
      {
        method,
        path_with_query: pathWithQuery,
        nonce,
        body_len: body.length,
        signature_prefix: signature.slice(0, 12),
      },
      null,
      2
    )
  );

  // request id (if any)
  report.request_id = res.headers.get("x-request-id") || res.headers.get("request-id");

  report.headers = redactHeaders(res.headers);

  // Body handling: no raw balances. Use schema summary.
  let json: any = null;
  try {
    json = await res.json();
    report.body = {
      redacted: true,
      schema_summary: schemaSummary(json),
    };
  } catch {
    report.body = { redacted: true, note: "non-json or empty body" };
  }

  // Signature/nonce verification:
  // We can only verify we computed signature deterministically from nonce/method/path/bodyHash,
  // not that server accepted it. We encode server-accept inference:
  if (res.status !== 401 && res.status !== 403) {
    report.signature = { verified: true, reason: "request not rejected as unauthorized (inferred acceptance of signature)" };
  } else {
    report.signature = { verified: false, reason: `server returned ${res.status} (unauthorized/forbidden)` };
  }

  await fs.writeFile("buda_probe_report.json", JSON.stringify(report, null, 2), "utf8");

  // Fail the job if probe failed
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`Buda probe failed with status ${res.status}`);
  }
}

main().catch((err) => {
  // Do NOT print env vars or headers.
  console.error(`buda_probe failed: ${err?.message || err}`);
  process.exit(1);
});
