import assert from "node:assert/strict";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { createRepoFixture, expectViolation, initAndProtect, loadCore, NOW, PASSWORD } from "../helpers/repo-fixture.mjs";

test("initRepository creates signed repo-readable verification metadata without storing the password", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();

    const result = await core.initRepository({
      repoRoot: fixture.repoRoot,
      password: PASSWORD,
      now: NOW
    });

    assert.equal(result.ok, true);
    assert.match(result.manifestPath, /\.straight-jacket\/manifest\.json$/);
    assert.match(result.signaturePath, /\.straight-jacket\/manifest\.sig$/);
    assert.match(result.publicKeyPath, /\.straight-jacket\/public-key\.json$/);
    assert.match(result.fingerprint, /^sha256:[a-f0-9]+$/);

    const manifest = JSON.parse(await fixture.file(".straight-jacket/manifest.json"));
    assert.equal(manifest.version, 1);
    assert.equal(manifest.hashAlgorithm ?? manifest.hash_algorithm, "sha256");
    assert.deepEqual(manifest.entries, []);

    const repoState = [
      await fixture.file(".straight-jacket/manifest.json"),
      await fixture.file(".straight-jacket/manifest.sig"),
      await fixture.file(".straight-jacket/public-key.json")
    ].join("\n");
    assert.equal(repoState.includes(PASSWORD), false, "password must never be stored in repo metadata");
  } finally {
    await fixture.cleanup();
  }
});

test("initRepository refuses to overwrite existing Straight Jacket metadata", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    const first = await core.initRepository({
      repoRoot: fixture.repoRoot,
      password: PASSWORD,
      now: NOW
    });
    const manifestBefore = await fixture.file(".straight-jacket/manifest.json");
    const signatureBefore = await fixture.file(".straight-jacket/manifest.sig");
    const publicKeyBefore = await fixture.file(".straight-jacket/public-key.json");

    await assert.rejects(
      () => core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW }),
      /REPOSITORY_ALREADY_INITIALIZED/
    );

    assert.equal(await fixture.file(".straight-jacket/manifest.json"), manifestBefore);
    assert.equal(await fixture.file(".straight-jacket/manifest.sig"), signatureBefore);
    assert.equal(await fixture.file(".straight-jacket/public-key.json"), publicKeyBefore);
    assert.equal(first.fingerprint, JSON.parse(publicKeyBefore).fingerprint);
  } finally {
    await fixture.cleanup();
  }
});

test("addProtectedFile registers path, basename, checksum, size, timestamp, reason, and re-signs manifest", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW });

    const result = await core.addProtectedFile({
      repoRoot: fixture.repoRoot,
      path: "docs/policy.md",
      password: PASSWORD,
      reason: "Human-owned policy file",
      now: NOW
    });

    assert.equal(result.ok, true);
    assert.equal(result.entry.path, "docs/policy.md");
    assert.equal(result.entry.name, "policy.md");
    assert.match(result.entry.checksum, /^sha256:[a-f0-9]{64}$/);
    assert.equal(result.entry.size, Buffer.byteLength("# Policy\n\nHuman-owned text.\n"));
    assert.equal(result.entry.registeredAt ?? result.entry.registered_at, NOW);
    assert.equal(result.entry.reason, "Human-owned policy file");

    const verify = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    assert.deepEqual(verify, { ok: true, checked: 1, violations: [] });
  } finally {
    await fixture.cleanup();
  }
});

test("addProtectedFiles registers multiple paths and glob matches with one authorization", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW });

    const result = await core.addProtectedFiles({
      repoRoot: fixture.repoRoot,
      paths: ["docs/*.md"],
      password: PASSWORD,
      reason: "Human-owned docs",
      now: NOW
    });

    assert.equal(result.ok, true);
    assert.deepEqual(result.entries.map((entry) => entry.path), [
      "docs/other.md",
      "docs/policy.md"
    ]);
    assert.equal(result.entries[0].reason, "Human-owned docs");

    const verify = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    assert.deepEqual(verify, { ok: true, checked: 2, violations: [] });
  } finally {
    await fixture.cleanup();
  }
});

test("removeProtectedFile requires the human password and re-signs the manifest", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);

    await assert.rejects(
      () => core.removeProtectedFile({ repoRoot: fixture.repoRoot, path: "docs/policy.md", password: "wrong" }),
      /AUTHORIZATION_REQUIRED|INVALID_PASSWORD|SIGNING_FAILED/
    );

    const result = await core.removeProtectedFile({
      repoRoot: fixture.repoRoot,
      path: "docs/policy.md",
      password: PASSWORD
    });

    assert.equal(result.ok, true);
    assert.equal(result.removedPath, "docs/policy.md");

    const verify = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    assert.deepEqual(verify, { ok: true, checked: 0, violations: [] });
  } finally {
    await fixture.cleanup();
  }
});

test("removeProtectedFiles unregisters every protected path matched by a glob pattern", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW });
    await core.addProtectedFiles({
      repoRoot: fixture.repoRoot,
      paths: ["docs/*.md"],
      password: PASSWORD,
      reason: "Human-owned docs",
      now: NOW
    });

    const result = await core.removeProtectedFiles({
      repoRoot: fixture.repoRoot,
      paths: ["docs/*.md"],
      password: PASSWORD
    });

    assert.equal(result.ok, true);
    assert.deepEqual(result.removedPaths, [
      "docs/other.md",
      "docs/policy.md"
    ]);

    const verify = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    assert.deepEqual(verify, { ok: true, checked: 0, violations: [] });
  } finally {
    await fixture.cleanup();
  }
});

test("updateProtectedFile accepts changed content only through human authorization", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await fixture.write("docs/policy.md", "# Policy\n\nHuman-approved replacement.\n");

    const beforeUpdate = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    expectViolation(beforeUpdate, "CHECKSUM_MISMATCH", "docs/policy.md");

    await assert.rejects(
      () => core.updateProtectedFile({ repoRoot: fixture.repoRoot, path: "docs/policy.md", password: "wrong", now: NOW }),
      /AUTHORIZATION_REQUIRED|INVALID_PASSWORD|SIGNING_FAILED/
    );

    const result = await core.updateProtectedFile({
      repoRoot: fixture.repoRoot,
      path: "docs/policy.md",
      password: PASSWORD,
      now: NOW
    });

    assert.equal(result.ok, true);
    assert.equal(result.entry.path, "docs/policy.md");
    assert.match(result.entry.checksum, /^sha256:[a-f0-9]{64}$/);

    const afterUpdate = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    assert.deepEqual(afterUpdate, { ok: true, checked: 1, violations: [] });
  } finally {
    await fixture.cleanup();
  }
});

test("renameProtectedFile is the only valid path-change flow", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await rename(path.join(fixture.repoRoot, "docs", "policy.md"), path.join(fixture.repoRoot, "docs", "policy-renamed.md"));

    const implicitMove = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    expectViolation(implicitMove, "PROTECTED_FILE_MISSING", "docs/policy.md");
    expectViolation(implicitMove, "LIKELY_RENAME_OR_MOVE", "docs/policy-renamed.md");

    const result = await core.renameProtectedFile({
      repoRoot: fixture.repoRoot,
      from: "docs/policy.md",
      to: "docs/policy-renamed.md",
      password: PASSWORD,
      now: NOW
    });

    assert.equal(result.ok, true);
    assert.equal(result.from, "docs/policy.md");
    assert.equal(result.to, "docs/policy-renamed.md");

    const afterRename = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    assert.deepEqual(afterRename, { ok: true, checked: 1, violations: [] });
  } finally {
    await fixture.cleanup();
  }
});

test("verifyRepository is read-only and reports stable violation objects", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);

    const beforeManifest = await readFile(path.join(fixture.repoRoot, ".straight-jacket", "manifest.json"), "utf8");
    const beforeSignature = await readFile(path.join(fixture.repoRoot, ".straight-jacket", "manifest.sig"), "utf8");

    await fixture.write("docs/policy.md", "# Policy\n\nAI changed this.\n");
    const result = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });

    expectViolation(result, "CHECKSUM_MISMATCH", "docs/policy.md");
    const violation = result.violations.find((item) => item.code === "CHECKSUM_MISMATCH");
    assert.equal(typeof violation.message, "string");
    assert.match(violation.expected, /^sha256:/);
    assert.match(violation.actual, /^sha256:/);

    assert.equal(await readFile(path.join(fixture.repoRoot, ".straight-jacket", "manifest.json"), "utf8"), beforeManifest);
    assert.equal(await readFile(path.join(fixture.repoRoot, ".straight-jacket", "manifest.sig"), "utf8"), beforeSignature);
  } finally {
    await fixture.cleanup();
  }
});

test("listProtectedFiles returns signed public metadata without private signing material", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);

    const result = await core.listProtectedFiles({ repoRoot: fixture.repoRoot });

    assert.equal(result.ok, true);
    assert.equal(result.entries.length, 1);
    assert.equal(result.entries[0].path, "docs/policy.md");
    assert.equal(JSON.stringify(result).includes(PASSWORD), false);
    assert.equal(JSON.stringify(result).includes("privateKey"), false);
  } finally {
    await fixture.cleanup();
  }
});

test("getRepositoryStatus reports hook health and strong-mode enforcement posture", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW });

    const beforeHook = await core.getRepositoryStatus({ repoRoot: fixture.repoRoot });
    assert.equal(beforeHook.ok, true);
    assert.equal(beforeHook.hook.installed, false);
    assert.equal(beforeHook.enforcement.localHookAdvisory, true);
    assert.equal(beforeHook.enforcement.requiresExternalVerifierForStrongMode, true);

    await core.installHook({ repoRoot: fixture.repoRoot });
    const afterHook = await core.getRepositoryStatus({ repoRoot: fixture.repoRoot });
    assert.equal(afterHook.hook.installed, true);
  } finally {
    await fixture.cleanup();
  }
});

test("installHook installs an advisory pre-commit hook that runs full and staged verification", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW });

    const result = await core.installHook({ repoRoot: fixture.repoRoot });

    assert.equal(result.ok, true);
    assert.equal(result.hook.installed, true);
    assert.match(result.hook.path, /\.git\/hooks\/pre-commit$/);
    const hook = await readFile(result.hook.path, "utf8");
    assert.match(hook, /straight-jacket verify && straight-jacket verify --staged/);
  } finally {
    await fixture.cleanup();
  }
});

test("installCi creates a verifier template with external fingerprint pinning guidance", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW });

    const result = await core.installCi({
      repoRoot: fixture.repoRoot,
      provider: "github-actions"
    });

    assert.equal(result.ok, true);
    assert.equal(result.provider, "github-actions");
    assert.equal(result.path, ".github/workflows/straight-jacket.yml");
    const workflow = await fixture.file(".github/workflows/straight-jacket.yml");
    assert.match(workflow, /straight-jacket verify/);
    assert.match(workflow, /STRAIGHT_JACKET_PUBLIC_KEY_FINGERPRINT/);
  } finally {
    await fixture.cleanup();
  }
});

test("path registration rejects absolute paths, parent escapes, symlinks, duplicates, and case collisions", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW });

    await assert.rejects(
      () => core.addProtectedFile({ repoRoot: fixture.repoRoot, path: path.join(fixture.repoRoot, "docs/policy.md"), password: PASSWORD, now: NOW }),
      /INVALID_PATH_ABSOLUTE/
    );

    await assert.rejects(
      () => core.addProtectedFile({ repoRoot: fixture.repoRoot, path: "../outside.md", password: PASSWORD, now: NOW }),
      /INVALID_PATH_ESCAPE/
    );

    await fixture.symlink("docs/policy.md", "docs/policy-link.md");
    await assert.rejects(
      () => core.addProtectedFile({ repoRoot: fixture.repoRoot, path: "docs/policy-link.md", password: PASSWORD, now: NOW }),
      /SYMLINK_NOT_ALLOWED/
    );

    await core.addProtectedFile({ repoRoot: fixture.repoRoot, path: "docs/policy.md", password: PASSWORD, now: NOW });
    await assert.rejects(
      () => core.addProtectedFile({ repoRoot: fixture.repoRoot, path: "docs/policy.md", password: PASSWORD, now: NOW }),
      /DUPLICATE_PROTECTED_PATH/
    );

    await mkdir(path.join(fixture.repoRoot, "DOCS"), { recursive: true });
    await writeFile(path.join(fixture.repoRoot, "DOCS", "POLICY.md"), "# Different casing\n");
    await assert.rejects(
      () => core.addProtectedFile({ repoRoot: fixture.repoRoot, path: "DOCS/POLICY.md", password: PASSWORD, now: NOW }),
      /PATH_CASE_COLLISION/
    );
  } finally {
    await fixture.cleanup();
  }
});
