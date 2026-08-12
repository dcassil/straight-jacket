import assert from "node:assert/strict";
import test from "node:test";

test("plugin skill policy lists required first checks and forbidden actions", async () => {
  const { buildSkillPolicy } = await import("../../src/plugin/skills/policy.js");

  const policy = buildSkillPolicy();

  assert.deepEqual(policy.requiredFirstChecks, [
    "straight-jacket list --json",
    "straight-jacket verify --json"
  ]);
  assert.ok(policy.forbiddenActions.includes("edit .straight-jacket/manifest.json"));
  assert.ok(policy.forbiddenActions.includes("edit .straight-jacket/manifest.sig"));
  assert.ok(policy.forbiddenActions.includes("edit .straight-jacket/public-key.json"));
  assert.ok(policy.forbiddenActions.includes("ask user for password in chat"));
  assert.ok(policy.forbiddenActions.includes("commit with --no-verify to bypass checks"));
});

test("plugin MCP manifest references only read-only MCP tools", async () => {
  const { buildPluginMcpManifest } = await import("../../src/plugin/mcp/manifest.js");

  const manifest = buildPluginMcpManifest();
  const toolNames = manifest.tools.map((tool) => tool.name).sort();

  assert.deepEqual(toolNames, [
    "straight_jacket_explain_violation",
    "straight_jacket_list_protected_files",
    "straight_jacket_verify"
  ]);
  assert.equal(JSON.stringify(manifest).includes("straight_jacket_update"), false);
  assert.equal(JSON.stringify(manifest).includes("straight_jacket_capture_password"), false);
});
