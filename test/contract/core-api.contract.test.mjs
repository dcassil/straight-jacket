import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { createRepoFixture, expectViolation, initAndProtect, loadCore, LOCAL_PASSWORD, MASTER_PASSWORD, NOW, PASSWORD } from "../helpers/repo-fixture.mjs";

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
    assert.match(result.signersPath, /\.straight-jacket\/signers\.json$/);
    assert.match(result.signersSignaturePath, /\.straight-jacket\/signers\.sig$/);
    assert.match(result.registrationPublicKeyPath, /\.straight-jacket\/registration-public-key\.json$/);
    assert.match(result.registrationKeyPath, /\.straight-jacket\/registration-key\.enc\.json$/);
    assert.match(result.ciProofPath, /\.straight-jacket\/ci-proof\.json$/);
    assert.match(result.fingerprint, /^sha256:[a-f0-9]+$/);
    assert.match(result.localSignerKeyId, /^sha256:[a-f0-9]+$/);
    assert.equal(result.ci.secretName, "STRAIGHT_JACKET_CI_KEY");
    assert.match(result.ci.ciKey, /^sjci_v1_/);

    const manifest = JSON.parse(await fixture.file(".straight-jacket/manifest.json"));
    assert.equal(manifest.version, 1);
    assert.equal(manifest.hashAlgorithm ?? manifest.hash_algorithm, "sha256");
    assert.deepEqual(manifest.entries, []);

    const repoState = [
      await fixture.file(".straight-jacket/manifest.json"),
      await fixture.file(".straight-jacket/manifest.sig"),
      await fixture.file(".straight-jacket/signers.json"),
      await fixture.file(".straight-jacket/signers.sig"),
      await fixture.file(".straight-jacket/registration-public-key.json"),
      await fixture.file(".straight-jacket/registration-key.enc.json"),
      await fixture.file(".straight-jacket/ci-proof.json")
    ].join("\n");
    assert.equal(repoState.includes(PASSWORD), false, "password must never be stored in repo metadata");
    assert.equal(repoState.includes(result.ci.ciKey), false, "CI key must never be stored in repo metadata");

    const verify = await core.verifyRepository({
      repoRoot: fixture.repoRoot,
      scope: "working-tree",
      ciKey: result.ci.ciKey
    });
    assert.deepEqual(verify, { ok: true, checked: 0, violations: [] });

    expectViolation(await core.verifyRepository({
      repoRoot: fixture.repoRoot,
      scope: "working-tree",
      ciKey: ""
    }), "CI_KEY_INVALID");
  } finally {
    await fixture.cleanup();
  }
});

test("CI key accepts reinitialized metadata only when the same master password is used", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    const initial = await core.initRepository({
      repoRoot: fixture.repoRoot,
      masterPassword: MASTER_PASSWORD,
      localPassword: LOCAL_PASSWORD,
      now: NOW
    });
    const originalCiKey = initial.ci.ciKey;

    await rm(path.join(fixture.repoRoot, ".straight-jacket"), { recursive: true, force: true });
    await core.initRepository({
      repoRoot: fixture.repoRoot,
      masterPassword: MASTER_PASSWORD,
      localPassword: "new local password",
      now: NOW
    });

    assert.deepEqual(await core.verifyRepository({
      repoRoot: fixture.repoRoot,
      scope: "working-tree",
      ciKey: originalCiKey
    }), { ok: true, checked: 0, violations: [] });

    await rm(path.join(fixture.repoRoot, ".straight-jacket"), { recursive: true, force: true });
    await core.initRepository({
      repoRoot: fixture.repoRoot,
      masterPassword: "different master password",
      localPassword: "new local password",
      now: NOW
    });

    expectViolation(await core.verifyRepository({
      repoRoot: fixture.repoRoot,
      scope: "working-tree",
      ciKey: originalCiKey
    }), "CI_PROOF_INVALID");
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
    const signersBefore = await fixture.file(".straight-jacket/signers.json");
    const registrationPublicKeyBefore = await fixture.file(".straight-jacket/registration-public-key.json");

    await assert.rejects(
      () => core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW }),
      /REPOSITORY_ALREADY_INITIALIZED/
    );

    assert.equal(await fixture.file(".straight-jacket/manifest.json"), manifestBefore);
    assert.equal(await fixture.file(".straight-jacket/manifest.sig"), signatureBefore);
    assert.equal(await fixture.file(".straight-jacket/signers.json"), signersBefore);
    assert.equal(await fixture.file(".straight-jacket/registration-public-key.json"), registrationPublicKeyBefore);
    assert.equal(first.fingerprint, JSON.parse(registrationPublicKeyBefore).fingerprint);
  } finally {
    await fixture.cleanup();
  }
});

test("master password registers users but cannot mutate protected files", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({
      repoRoot: fixture.repoRoot,
      masterPassword: MASTER_PASSWORD,
      localPassword: LOCAL_PASSWORD,
      now: NOW
    });

    await assert.rejects(
      () => core.addProtectedFile({
        repoRoot: fixture.repoRoot,
        path: "docs/policy.md",
        password: MASTER_PASSWORD,
        reason: "Human-owned policy file",
        now: NOW
      }),
      /INVALID_PASSWORD/
    );

    const result = await core.addProtectedFile({
      repoRoot: fixture.repoRoot,
      path: "docs/policy.md",
      password: LOCAL_PASSWORD,
      reason: "Human-owned policy file",
      now: NOW
    });

    assert.equal(result.ok, true);
  } finally {
    await fixture.cleanup();
  }
});

test("setupRepository registers a fresh clone only after protected files verify", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({
      repoRoot: fixture.repoRoot,
      masterPassword: MASTER_PASSWORD,
      localPassword: LOCAL_PASSWORD,
      now: NOW
    });
    await core.addProtectedFile({
      repoRoot: fixture.repoRoot,
      path: "docs/policy.md",
      password: LOCAL_PASSWORD,
      reason: "Human-owned policy file",
      now: NOW
    });
    await rm(path.join(fixture.repoRoot, ".straight-jacket", "local"), { recursive: true, force: true });

    const missing = await assert.rejects(
      () => core.checkRepositorySetup({ repoRoot: fixture.repoRoot }),
      /LOCAL_SIGNER_MISSING/
    );
    assert.equal(missing, undefined);

    const setup = await core.setupRepository({
      repoRoot: fixture.repoRoot,
      masterPassword: MASTER_PASSWORD,
      localPassword: "fresh clone local password",
      now: NOW
    });

    assert.equal(setup.ok, true);
    assert.equal(setup.registered, true);
    assert.match(setup.signerKeyId, /^sha256:/);
    assert.equal(setup.ci.secretName, "STRAIGHT_JACKET_CI_KEY");
    assert.match(setup.ci.ciKey, /^sjci_v1_/);
    const signers = JSON.parse(await fixture.file(".straight-jacket/signers.json"));
    assert.equal(signers.signers.length, 2);
  } finally {
    await fixture.cleanup();
  }
});

test("setupRepository upgrades legacy metadata after verifying locked files", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await writeLegacyMetadata(fixture.repoRoot);

    const setup = await core.setupRepository({
      repoRoot: fixture.repoRoot,
      masterPassword: MASTER_PASSWORD,
      localPassword: LOCAL_PASSWORD,
      now: NOW
    });

    assert.equal(setup.ok, true);
    assert.equal(setup.upgraded, true);
    assert.equal(setup.registered, true);
    assert.equal(setup.ci.secretName, "STRAIGHT_JACKET_CI_KEY");
    assert.equal(await fixture.exists(".straight-jacket/public-key.json"), false);
    assert.equal(await fixture.exists(".straight-jacket/signers.json"), true);
    assert.equal(await fixture.exists(".straight-jacket/signers.sig"), true);
    assert.equal(await fixture.exists(".straight-jacket/registration-public-key.json"), true);
    assert.equal(await fixture.exists(".straight-jacket/registration-key.enc.json"), true);
    assert.equal(await fixture.exists(".straight-jacket/ci-proof.json"), true);

    assert.deepEqual(await core.verifyRepository({
      repoRoot: fixture.repoRoot,
      scope: "working-tree",
      ciKey: setup.ci.ciKey
    }), { ok: true, checked: 1, violations: [] });
  } finally {
    await fixture.cleanup();
  }
});

test("setupRepository refuses to register a local signer while locked files are dirty", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({
      repoRoot: fixture.repoRoot,
      masterPassword: MASTER_PASSWORD,
      localPassword: LOCAL_PASSWORD,
      now: NOW
    });
    await core.addProtectedFile({
      repoRoot: fixture.repoRoot,
      path: "docs/policy.md",
      password: LOCAL_PASSWORD,
      reason: "Human-owned policy file",
      now: NOW
    });
    await rm(path.join(fixture.repoRoot, ".straight-jacket", "local"), { recursive: true, force: true });
    await fixture.write("docs/policy.md", "# Policy\n\nDirty before setup.\n");

    const setup = await core.setupRepository({
      repoRoot: fixture.repoRoot,
      masterPassword: MASTER_PASSWORD,
      localPassword: "fresh clone local password",
      now: NOW
    });

    assert.equal(setup.ok, false);
    expectViolation(setup, "CHECKSUM_MISMATCH", "docs/policy.md");
    assert.equal(await fixture.exists(".straight-jacket/local/private-key.json"), false);
  } finally {
    await fixture.cleanup();
  }
});

async function writeLegacyMetadata(repoRoot, entryPath = "docs/policy.md") {
  const { canonicalizeJson } = await import("../../src/manifest/canonical-json.js");
  const { createSigningKey, exportPublicKey } = await import("../../src/signing/keys.js");
  const { signPayload } = await import("../../src/signing/signatures.js");
  const keyPair = await createSigningKey();
  const publicKey = await exportPublicKey(keyPair);
  const content = await readFile(path.join(repoRoot, entryPath));
  const manifest = {
    version: 1,
    repoId: `sha256:${createHash("sha256").update(repoRoot).digest("hex")}`,
    hashAlgorithm: "sha256",
    signatureAlgorithm: "ed25519",
    keyId: publicKey.keyId,
    policy: {
      allowSymlinks: false,
      requireHumanAuthorization: true,
      failClosed: true
    },
    entries: [
      {
        path: entryPath,
        name: path.basename(entryPath),
        checksum: `sha256:${createHash("sha256").update(content).digest("hex")}`,
        size: content.length,
        registeredAt: NOW,
        reason: "Legacy protected file"
      }
    ]
  };
  const signature = await signPayload({
    payload: canonicalizeJson(manifest),
    privateKey: keyPair.privateKey,
    keyId: publicKey.keyId,
    now: NOW
  });

  await mkdir(path.join(repoRoot, ".straight-jacket"), { recursive: true });
  await writeFile(path.join(repoRoot, ".straight-jacket", "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(path.join(repoRoot, ".straight-jacket", "manifest.sig"), `${JSON.stringify(signature, null, 2)}\n`);
  await writeFile(path.join(repoRoot, ".straight-jacket", "public-key.json"), `${JSON.stringify(publicKey, null, 2)}\n`);
}

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

test("addProtectedFiles registers shell-expanded path lists and removeProtectedFiles removes manifest pattern matches", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW });
    await fixture.write("tools/pre-commit-alpha", "#!/bin/sh\n");
    await fixture.write("tools/pre-commit-beta", "#!/bin/sh\n");

    const add = await core.addProtectedFiles({
      repoRoot: fixture.repoRoot,
      paths: ["tools/pre-commit-alpha", "tools/pre-commit-beta"],
      password: PASSWORD,
      reason: "Hook scripts",
      now: NOW
    });

    assert.equal(add.ok, true);
    assert.deepEqual(add.entries.map((entry) => entry.path), [
      "tools/pre-commit-alpha",
      "tools/pre-commit-beta"
    ]);

    const remove = await core.removeProtectedFiles({
      repoRoot: fixture.repoRoot,
      paths: ["tools/pre-commit-*"],
      password: PASSWORD,
      now: NOW
    });

    assert.deepEqual(remove, {
      ok: true,
      removedPaths: [
        "tools/pre-commit-alpha",
        "tools/pre-commit-beta"
      ]
    });

    const verify = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    assert.deepEqual(verify, { ok: true, checked: 0, violations: [] });
  } finally {
    await fixture.cleanup();
  }
});

test("removeProtectedFiles skips shell-expanded unregistered paths and removes registered matches", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW });
    await fixture.write("something/somethingelse/alpha.py", "print('alpha')\n");
    await fixture.write("something/somethingelse/beta.py", "print('beta')\n");
    await fixture.write("something/other/unlocked.py", "print('other')\n");

    await core.addProtectedFiles({
      repoRoot: fixture.repoRoot,
      paths: [
        "something/somethingelse/alpha.py",
        "something/somethingelse/beta.py"
      ],
      password: PASSWORD,
      reason: "Python scripts",
      now: NOW
    });

    const remove = await core.removeProtectedFiles({
      repoRoot: fixture.repoRoot,
      paths: [
        "something/other/unlocked.py",
        "something/somethingelse/alpha.py",
        "something/somethingelse/beta.py"
      ],
      password: PASSWORD,
      now: NOW
    });

    assert.deepEqual(remove, {
      ok: true,
      removedPaths: [
        "something/somethingelse/alpha.py",
        "something/somethingelse/beta.py"
      ]
    });

    const verify = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    assert.deepEqual(verify, { ok: true, checked: 0, violations: [] });
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

test("updateProtectedFiles accepts multiple changed files with one authorization", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await core.addProtectedFile({
      repoRoot: fixture.repoRoot,
      path: "docs/other.md",
      password: PASSWORD,
      reason: "Human-owned companion file",
      now: NOW
    });
    await fixture.write("docs/policy.md", "# Policy\n\nHuman-approved replacement.\n");
    await fixture.write("docs/other.md", "# Other\n\nHuman-approved replacement.\n");

    const beforeUpdate = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    expectViolation(beforeUpdate, "CHECKSUM_MISMATCH", "docs/policy.md");
    expectViolation(beforeUpdate, "CHECKSUM_MISMATCH", "docs/other.md");

    await assert.rejects(
      () => core.updateProtectedFiles({
        repoRoot: fixture.repoRoot,
        paths: ["docs/policy.md", "docs/other.md"],
        password: "wrong",
        now: NOW
      }),
      /AUTHORIZATION_REQUIRED|INVALID_PASSWORD|SIGNING_FAILED/
    );

    const result = await core.updateProtectedFiles({
      repoRoot: fixture.repoRoot,
      paths: ["docs/policy.md", "docs/other.md"],
      password: PASSWORD,
      now: NOW
    });

    assert.equal(result.ok, true);
    assert.deepEqual(result.entries.map((entry) => entry.path), ["docs/policy.md", "docs/other.md"]);
    assert.ok(result.entries.every((entry) => /^sha256:[a-f0-9]{64}$/.test(entry.checksum)));

    const afterUpdate = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    assert.deepEqual(afterUpdate, { ok: true, checked: 2, violations: [] });
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
    assert.match(result.hook.path, /\.githooks\/pre-commit$/);
    assert.equal(result.hook.configuredHooksPath, ".githooks");
    const hook = await readFile(result.hook.path, "utf8");
    assert.match(hook, /straight-jacket setup --check/);
    assert.match(hook, /straight-jacket verify && straight-jacket verify --staged/);
  } finally {
    await fixture.cleanup();
  }
});

test("installCi creates a verifier template with CI key proof guidance", async () => {
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
    assert.doesNotMatch(workflow, /straight-jacket verify .*--json/);
    assert.match(workflow, /--ci-key "\$STRAIGHT_JACKET_CI_KEY"/);
    assert.match(workflow, /secrets\.STRAIGHT_JACKET_CI_KEY/);
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
