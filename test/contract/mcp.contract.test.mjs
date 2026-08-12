import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { createRepoFixture, initAndProtect, loadCore, loadMcp, PASSWORD } from "../helpers/repo-fixture.mjs";
import packageJson from "../../package.json" with { type: "json" };

test("MCP exposes only the required read-first tool surface by default", async () => {
  const mcp = await loadMcp();

  const tools = await mcp.listTools();
  const names = tools.map((tool) => tool.name).sort();

  assert.deepEqual(names, [
    "straight_jacket_explain_violation",
    "straight_jacket_list_protected_files",
    "straight_jacket_verify"
  ]);
});

test("MCP stdio initialize reports the package version", () => {
  const result = spawnSync(process.execPath, [path.join(process.cwd(), "bin", "straight-jacket-mcp.mjs")], {
    input: `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })}\n`,
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr);
  const response = JSON.parse(result.stdout.trim());
  assert.equal(response.result.serverInfo.name, "straight-jacket");
  assert.equal(response.result.serverInfo.version, packageJson.version);
});

test("MCP list tool returns protected file metadata without private signing material", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    const mcp = await loadMcp();
    await initAndProtect(core, fixture.repoRoot);

    const result = await mcp.callTool("straight_jacket_list_protected_files", {
      repoRoot: fixture.repoRoot
    });

    assert.equal(result.ok, true);
    assert.equal(result.entries.length, 1);
    assert.equal(result.entries[0].path, "docs/policy.md");
    assert.equal(JSON.stringify(result).includes(PASSWORD), false);
    assert.equal(JSON.stringify(result).includes("privateKey"), false);
  } finally {
    await fixture.cleanup();
  }
});

test("MCP verify tool is read-only and reports the same stable violation contract as core", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    const mcp = await loadMcp();
    await initAndProtect(core, fixture.repoRoot);
    await fixture.write("docs/policy.md", "# Policy\n\nAI changed this.\n");

    const result = await mcp.callTool("straight_jacket_verify", {
      repoRoot: fixture.repoRoot,
      scope: "working-tree"
    });

    assert.equal(result.ok, false);
    assert.equal(result.violations[0].code, "CHECKSUM_MISMATCH");
    assert.equal(result.violations[0].path, "docs/policy.md");
  } finally {
    await fixture.cleanup();
  }
});

test("MCP rejects silent mutation, password capture, and private key export capabilities", async () => {
  const mcp = await loadMcp();

  const forbiddenNames = [
    "straight_jacket_add",
    "straight_jacket_remove",
    "straight_jacket_update",
    "straight_jacket_rename",
    "straight_jacket_capture_password",
    "straight_jacket_export_private_key"
  ];

  for (const name of forbiddenNames) {
    await assert.rejects(
      () => mcp.callTool(name, {}),
      /TOOL_NOT_FOUND|MUTATION_NOT_ALLOWED|FORBIDDEN_TOOL/
    );
  }
});

test("MCP explain tool turns violation codes into human-safe remediation instructions", async () => {
  const mcp = await loadMcp();

  const result = await mcp.callTool("straight_jacket_explain_violation", {
    violation: {
      code: "CHECKSUM_MISMATCH",
      path: "docs/policy.md",
      expected: "sha256:abc",
      actual: "sha256:def"
    }
  });

  assert.equal(result.ok, true);
  assert.match(result.message, /docs\/policy\.md/);
  assert.match(result.message, /straight-jacket update docs\/policy\.md/);
  assert.doesNotMatch(result.message, /password|private key/i);
});
