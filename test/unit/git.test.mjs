import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { createRepoFixture, runGit } from "../helpers/repo-fixture.mjs";

test("git path helpers reject absolute paths and parent escapes while preserving repo-relative slash paths", async () => {
  const fixture = await createRepoFixture();
  try {
    const { normalizeRepoPath, resolveRepoPath } = await import("../../src/git/paths.js");

    assert.equal(normalizeRepoPath("docs\\policy.md"), "docs/policy.md");
    assert.throws(() => normalizeRepoPath(path.join(fixture.repoRoot, "docs/policy.md")), /INVALID_PATH_ABSOLUTE/);
    assert.throws(() => normalizeRepoPath("../outside.md"), /INVALID_PATH_ESCAPE/);

    const resolved = resolveRepoPath(fixture.repoRoot, "docs/policy.md");
    assert.equal(resolved, path.join(fixture.repoRoot, "docs", "policy.md"));
  } finally {
    await fixture.cleanup();
  }
});

test("git repo helper confirms the exact repository root", async () => {
  const fixture = await createRepoFixture();
  try {
    const { assertGitRepoRoot } = await import("../../src/git/repo.js");

    assert.equal(await assertGitRepoRoot(fixture.repoRoot), fixture.repoRoot);
    await assert.rejects(() => assertGitRepoRoot(path.join(fixture.repoRoot, "docs")), /GIT_REPO_REQUIRED/);
  } finally {
    await fixture.cleanup();
  }
});

test("git staged helper reports staged deletions and staged manifest changes", async () => {
  const fixture = await createRepoFixture();
  try {
    const { getStagedChanges } = await import("../../src/git/staged.js");

    await fixture.mkdir(".straight-jacket");
    await fixture.write(".straight-jacket/manifest.json", '{"version":1,"entries":[]}');
    runGit(fixture.repoRoot, ["add", "."]);
    runGit(fixture.repoRoot, ["commit", "-m", "baseline"]);
    await fixture.write(".straight-jacket/manifest.json", '{"version":1,"entries":[1]}');
    await fixture.write("docs/policy.md", "");
    runGit(fixture.repoRoot, ["add", ".straight-jacket/manifest.json"]);
    runGit(fixture.repoRoot, ["rm", "-f", "docs/policy.md"]);

    const changes = await getStagedChanges(fixture.repoRoot);

    assert.ok(changes.some((change) => change.path === ".straight-jacket/manifest.json" && change.status === "modified"));
    assert.ok(changes.some((change) => change.path === "docs/policy.md" && change.status === "deleted"));
  } finally {
    await fixture.cleanup();
  }
});
