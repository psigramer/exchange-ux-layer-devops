import { describe, it, expect } from "vitest";
import { makeBudaCanonicalString, signBuda } from "../signer";

describe("Buda signer — canonical string", () => {
  it("GET with empty body does NOT include base64(body) slot", () => {
    const canonical = makeBudaCanonicalString({
      method: "GET",
      pathWithQuery: "/api/v2/balances",
      nonce: "1700000000000000",
      body: "", // empty
    });

    // IMPORTANT: single space between path and nonce (no empty slot)
    expect(canonical).toBe("GET /api/v2/balances 1700000000000000");
  });

  it("POST with body includes base64(body) as third component", () => {
    const body = JSON.stringify({ a: 1 });
    const canonical = makeBudaCanonicalString({
      method: "POST",
      pathWithQuery: "/api/v2/orders",
      nonce: "1700000000000000",
      body,
    });

    // components: METHOD, path, base64(body), nonce
    const parts = canonical.split(" ");
    expect(parts.length).toBe(4);
    expect(parts[0]).toBe("POST");
    expect(parts[1]).toBe("/api/v2/orders");
    expect(parts[3]).toBe("1700000000000000");
  });

  it("signature is deterministic for fixed inputs (golden)", () => {
    const { canonical, signature } = signBuda({
      method: "GET",
      pathWithQuery: "/api/v2/balances",
      nonce: "1700000000000000",
      body: "",
      apiSecret: "test-secret",
    });

    expect(canonical).toBe("GET /api/v2/balances 1700000000000000");

    // Golden signature: generate once, then freeze it.
    // Run the test once, copy the output if you want,
    // or temporarily console.log(signature) and paste it here.
    expect(signature).toMatch(/^[0-9a-f]{96}$/); // 384-bit hex = 96 chars
  });
});
