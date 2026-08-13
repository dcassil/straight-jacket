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
  assert.equal(policy.setupGuidance.cliMissing, "npm install -g github:dcassil/straight-jacket");
  assert.equal(policy.setupGuidance.projectNotInitialized, "straight-jacket setup");
  assert.equal(policy.setupGuidance.mcpNotConnected, "[mcp_servers.straight-jacket]");
  assert.equal(policy.setupGuidance.githubProtectionGuide, "docs/features/github-protection.md");
  assert.equal(policy.githubProtectionChecks.requiredStatusCheck, "verify");
  assert.equal(policy.githubProtectionChecks.requirePullRequestBeforeMerging, true);
  assert.equal(policy.githubProtectionChecks.enforceAdmins, true);
  assert.ok(policy.forbiddenActions.includes("edit .straight-jacket/manifest.json"));
  assert.ok(policy.forbiddenActions.includes("edit .straight-jacket/manifest.sig"));
  assert.ok(policy.forbiddenActions.includes("edit .straight-jacket/signers.json"));
  assert.ok(policy.forbiddenActions.includes("edit .straight-jacket/registration-public-key.json"));
  assert.ok(policy.forbiddenActions.includes("ask user for CI key in chat"));
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

test("MCP config examples use the installed MCP binary", async () => {
  const mcpConfig = JSON.parse(await readFile(new URL("../../.mcp.json", import.meta.url), "utf8"));
  const codexConfig = await readFile(new URL("../../codex/config.toml", import.meta.url), "utf8");
  const readme = await readFile(new URL("../../README.md", import.meta.url), "utf8");

  assert.equal(mcpConfig.mcpServers["straight-jacket"].command, "straight-jacket-mcp");
  assert.deepEqual(mcpConfig.mcpServers["straight-jacket"].args, []);
  assert.match(codexConfig, /command = "straight-jacket-mcp"/);
  assert.match(codexConfig, /args = \[\]/);
  assert.match(readme, /straight-jacket-mcp/);
  assert.doesNotMatch(readme, /pointing the `args` path/);
});

test("plugin skill template documents first checks and forbidden actions", async () => {
  const template = await readFile(new URL("../../templates/plugin/SKILL.md", import.meta.url), "utf8");
  const packagedSkill = await readFile(new URL("../../skills/straight-jacket/SKILL.md", import.meta.url), "utf8");

  for (const skillText of [template, packagedSkill]) {
    assert.match(skillText, /straight-jacket list --json/);
    assert.match(skillText, /straight-jacket verify --json/);
    assert.match(skillText, /Setup And Missing Configuration Guidance/);
    assert.match(skillText, /command -v straight-jacket/);
    assert.match(skillText, /npm install -g github:dcassil\/straight-jacket/);
    assert.match(skillText, /Before using Straight Jacket, you need to initialize it in this project/);
    assert.match(skillText, /straight-jacket setup/);
    assert.match(skillText, /\[mcp_servers\.straight-jacket\]/);
    assert.match(skillText, /GitHub Protection Guidance/);
    assert.match(skillText, /requires a pull request before merging/);
    assert.match(skillText, /requires the `verify` status check/);
    assert.match(skillText, /STRAIGHT_JACKET_CI_KEY/);
    assert.match(skillText, /gh api "repos\/OWNER\/REPO\/branches\/main\/protection"/);
    assert.match(skillText, /edit \.straight-jacket\/manifest\.json/);
    assert.match(skillText, /edit \.straight-jacket\/manifest\.sig/);
    assert.match(skillText, /edit \.straight-jacket\/signers\.json/);
    assert.match(skillText, /edit \.straight-jacket\/registration-public-key\.json/);
    assert.match(skillText, /ask user for password in chat/);
    assert.match(skillText, /commit with --no-verify to bypass checks/);
  }
});

test("hook and CI templates include staged verification and CI key guidance", async () => {
  const hook = await readFile(new URL("../../templates/hooks/pre-commit", import.meta.url), "utf8");
  const workflow = await readFile(new URL("../../templates/ci/github-action.yml", import.meta.url), "utf8");

  assert.match(hook, /straight-jacket:start/);
  assert.match(hook, /straight-jacket setup --check/);
  assert.match(hook, /straight-jacket verify && straight-jacket verify --staged/);
  assert.match(hook, /straight-jacket:end/);
  assert.match(workflow, /straight-jacket verify/);
  assert.match(workflow, /npm install -g straight-jacket/);
  assert.match(workflow, /STRAIGHT_JACKET_CI_KEY/);
  assert.match(workflow, /\$\{\{ secrets\.STRAIGHT_JACKET_CI_KEY \}\}/);
});
