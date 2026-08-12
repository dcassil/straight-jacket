import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createRepoFixture } from "../helpers/repo-fixture.mjs";

test("hook installer writes an idempotent pre-commit hook with stable markers", async () => {
  const fixture = await createRepoFixture();
  try {
    const { installPreCommitHook } = await import("../../src/hooks/install-hook.js");

    const first = await installPreCommitHook({ repoRoot: fixture.repoRoot });
    const second = await installPreCommitHook({ repoRoot: fixture.repoRoot });

    assert.equal(first.ok, true);
    assert.equal(second.ok, true);
    assert.equal(first.hook.path, second.hook.path);

    const hook = await readFile(first.hook.path, "utf8");
    assert.equal((hook.match(/straight-jacket:start/g) ?? []).length, 1);
    assert.equal((hook.match(/straight-jacket:end/g) ?? []).length, 1);
    assert.match(hook, /straight-jacket verify --staged/);
  } finally {
    await fixture.cleanup();
  }
});

test("hook status reports advisory local enforcement posture", async () => {
  const fixture = await createRepoFixture();
  try {
    const { getHookStatus } = await import("../../src/hooks/status.js");

    const status = await getHookStatus({ repoRoot: fixture.repoRoot });

    assert.equal(status.installed, false);
    assert.match(status.path, /\.git\/hooks\/pre-commit$/);
    assert.equal(status.command, "straight-jacket verify --staged");
    assert.equal(status.localHookAdvisory, true);
  } finally {
    await fixture.cleanup();
  }
});
