import assert from "node:assert/strict";
import test from "node:test";

test("core violations create stable JSON-serializable violation objects", async () => {
  const { createViolation } = await import("../../src/core/violations.js");

  const violation = createViolation("CHECKSUM_MISMATCH", {
    path: "docs/policy.md",
    expected: "sha256:abc",
    actual: "sha256:def"
  });

  assert.deepEqual(violation, {
    code: "CHECKSUM_MISMATCH",
    path: "docs/policy.md",
    message: "docs/policy.md checksum changed",
    expected: "sha256:abc",
    actual: "sha256:def"
  });
  assert.doesNotThrow(() => JSON.stringify(violation));
});

test("core verification result builder preserves all violations and checked count", async () => {
  const { buildVerificationResult } = await import("../../src/core/verification-result.js");

  assert.deepEqual(buildVerificationResult({ checked: 2, violations: [] }), {
    ok: true,
    checked: 2,
    violations: []
  });

  assert.deepEqual(buildVerificationResult({
    checked: 2,
    violations: [{ code: "MANIFEST_MISSING" }, { code: "PUBLIC_KEY_MISSING" }]
  }), {
    ok: false,
    checked: 2,
    violations: [{ code: "MANIFEST_MISSING" }, { code: "PUBLIC_KEY_MISSING" }]
  });
});

test("core errors expose stable codes in thrown error messages", async () => {
  const { createCodedError } = await import("../../src/core/errors.js");

  const error = createCodedError("INVALID_PASSWORD", "Could not unlock signing key");

  assert.equal(error.code, "INVALID_PASSWORD");
  assert.match(error.message, /INVALID_PASSWORD/);
  assert.match(error.message, /Could not unlock signing key/);
});
