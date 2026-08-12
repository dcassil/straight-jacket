import assert from "node:assert/strict";
import test from "node:test";

test("MCP tool registry contains only the default read-only tools", async () => {
  const { createToolRegistry } = await import("../../src/mcp/tools.js");

  const registry = createToolRegistry();

  assert.deepEqual(registry.listTools().map((tool) => tool.name).sort(), [
    "straight_jacket_explain_violation",
    "straight_jacket_list_protected_files",
    "straight_jacket_verify"
  ]);
});

test("MCP tool schemas do not accept password or private-key fields", async () => {
  const { toolSchemas } = await import("../../src/mcp/tool-schemas.js");

  for (const schema of Object.values(toolSchemas)) {
    const serialized = JSON.stringify(schema);
    assert.equal(/password|privateKey|private_key/i.test(serialized), false, `${schema.name} must not expose secrets`);
  }
});

test("MCP violation explainer returns human-safe update instructions", async () => {
  const { explainViolation } = await import("../../src/mcp/explain-violation.js");

  const result = explainViolation({
    code: "CHECKSUM_MISMATCH",
    path: "docs/policy.md",
    expected: "sha256:abc",
    actual: "sha256:def"
  });

  assert.equal(result.ok, true);
  assert.match(result.message, /docs\/policy\.md/);
  assert.match(result.message, /straight-jacket update docs\/policy\.md/);
  assert.doesNotMatch(result.message, /password|private key/i);
});
