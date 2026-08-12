import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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

test("plugin skill template documents first checks and forbidden actions", async () => {
  const template = await readFile(new URL("../../templates/plugin/SKILL.md", import.meta.url), "utf8");

  assert.match(template, /straight-jacket list --json/);
  assert.match(template, /straight-jacket verify --json/);
  assert.match(template, /edit \.straight-jacket\/manifest\.json/);
  assert.match(template, /edit \.straight-jacket\/manifest\.sig/);
  assert.match(template, /edit \.straight-jacket\/public-key\.json/);
  assert.match(template, /ask user for password in chat/);
  assert.match(template, /commit with --no-verify to bypass checks/);
});

test("hook and CI templates include staged verification and external fingerprint guidance", async () => {
  const hook = await readFile(new URL("../../templates/hooks/pre-commit", import.meta.url), "utf8");
  const workflow = await readFile(new URL("../../templates/ci/github-action.yml", import.meta.url), "utf8");

  assert.match(hook, /straight-jacket:start/);
  assert.match(hook, /straight-jacket verify --staged/);
  assert.match(hook, /straight-jacket:end/);
  assert.match(workflow, /straight-jacket verify/);
  assert.match(workflow, /STRAIGHT_JACKET_PUBLIC_KEY_FINGERPRINT/);
});
