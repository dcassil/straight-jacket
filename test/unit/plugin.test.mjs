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

test("Claude plugin marketplace manifest points at the root plugin without path traversal", async () => {
  const pluginManifest = JSON.parse(await readFile(new URL("../../.claude-plugin/plugin.json", import.meta.url), "utf8"));
  const marketplace = JSON.parse(await readFile(new URL("../../.claude-plugin/marketplace.json", import.meta.url), "utf8"));

  assert.equal(marketplace.name, "straight-jacket");
  assert.equal(marketplace.owner.name, "Daniel Cassil");
  assert.equal(marketplace.owner.email, "me@danielcassil.com");
  assert.equal(marketplace.plugins.length, 1);

  const [plugin] = marketplace.plugins;
  assert.equal(plugin.name, pluginManifest.name);
  assert.equal(plugin.version, pluginManifest.version);
  assert.equal(plugin.source, ".");
  assert.equal(plugin.source.includes(".."), false);
  assert.match(plugin.description, /human-protected repo files/);
});

test("package metadata exposes CLI and MCP executable shims", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
  const cliShim = await readFile(new URL("../../bin/straight-jacket.mjs", import.meta.url), "utf8");
  const mcpShim = await readFile(new URL("../../bin/straight-jacket-mcp.mjs", import.meta.url), "utf8");

  assert.equal(packageJson.bin["straight-jacket"], "bin/straight-jacket.mjs");
  assert.equal(packageJson.bin["straight-jacket-mcp"], "bin/straight-jacket-mcp.mjs");
  assert.match(cliShim, /^#!\/usr\/bin\/env node/);
  assert.match(cliShim, /src\/cli\.js/);
  assert.match(mcpShim, /^#!\/usr\/bin\/env node/);
  assert.match(mcpShim, /src\/mcp\.js/);
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
