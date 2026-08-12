import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("GitHub workflows enforce version bump and release-on-main policy", async () => {
  const verifyWorkflow = await readFile(new URL("../../.github/workflows/straight-jacket.yml", import.meta.url), "utf8");
  const releaseWorkflow = await readFile(new URL("../../.github/workflows/release.yml", import.meta.url), "utf8");
  const agentRules = await readFile(new URL("../../AGENTS.md", import.meta.url), "utf8");

  assert.match(verifyWorkflow, /Ensure package version is unpublished/);
  assert.match(verifyWorkflow, /already published\. Bump the package version before merging to main/);
  assert.match(releaseWorkflow, /on:\n  push:\n    branches: \[main\]/);
  assert.match(releaseWorkflow, /npm publish --access public/);
  assert.match(releaseWorkflow, /secrets\.NPM_TOKEN/);
  assert.match(releaseWorkflow, /git push origin "\$\{\{ steps\.release\.outputs\.tag_name \}\}"/);
  assert.match(releaseWorkflow, /gh release create/);
  assert.match(agentRules, /Every PR intended for `main` must bump/);
  assert.match(agentRules, /Publishing is automatic on every push to `main`/);
});
