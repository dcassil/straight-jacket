import assert from "node:assert/strict";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { createRepoFixture, expectViolation, initAndProtect, loadCore, runGit, NOW, PASSWORD } from "../helpers/repo-fixture.mjs";

test("detects protected file content modification", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await fixture.write("docs/policy.md", "# Policy\n\nAI changed this.\n");

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "CHECKSUM_MISMATCH", "docs/policy.md");
  } finally {
    await fixture.cleanup();
  }
});

test("detects protected file deletion", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await rm(path.join(fixture.repoRoot, "docs", "policy.md"));

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "PROTECTED_FILE_MISSING", "docs/policy.md");
  } finally {
    await fixture.cleanup();
  }
});

test("detects protected file move or rename even when checksum is unchanged", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await rename(path.join(fixture.repoRoot, "docs", "policy.md"), path.join(fixture.repoRoot, "docs", "policy-renamed.md"));

    const result = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" });
    expectViolation(result, "PROTECTED_FILE_MISSING", "docs/policy.md");
    expectViolation(result, "LIKELY_RENAME_OR_MOVE", "docs/policy-renamed.md");
  } finally {
    await fixture.cleanup();
  }
});

test("detects direct manifest checksum editing without a valid signature", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    const manifestPath = path.join(fixture.repoRoot, ".straight-jacket", "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.entries[0].checksum = "sha256:" + "0".repeat(64);
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "MANIFEST_SIGNATURE_INVALID");
  } finally {
    await fixture.cleanup();
  }
});

test("detects manifest deletion", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await rm(path.join(fixture.repoRoot, ".straight-jacket", "manifest.json"));

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "MANIFEST_MISSING");
  } finally {
    await fixture.cleanup();
  }
});

test("detects signature deletion", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await rm(path.join(fixture.repoRoot, ".straight-jacket", "manifest.sig"));

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "MANIFEST_SIGNATURE_MISSING");
  } finally {
    await fixture.cleanup();
  }
});

test("detects registration public verifier deletion", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await rm(path.join(fixture.repoRoot, ".straight-jacket", "registration-public-key.json"));

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "REGISTRATION_PUBLIC_KEY_MISSING");
  } finally {
    await fixture.cleanup();
  }
});

test("detects registration public verifier replacement when trusted fingerprint is pinned externally", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    const init = await core.initRepository({ repoRoot: fixture.repoRoot, password: PASSWORD, now: NOW });
    await core.addProtectedFile({ repoRoot: fixture.repoRoot, path: "docs/policy.md", password: PASSWORD, reason: "Human-owned policy file", now: NOW });
    await writeFile(path.join(fixture.repoRoot, ".straight-jacket", "registration-public-key.json"), JSON.stringify({ algorithm: "ed25519", publicKey: "attacker-key" }));

    expectViolation(
      await core.verifyRepository({
        repoRoot: fixture.repoRoot,
        scope: "working-tree",
        trustedPublicKeyFingerprint: init.fingerprint
      }),
      "PUBLIC_KEY_FINGERPRINT_MISMATCH"
    );
  } finally {
    await fixture.cleanup();
  }
});

test("detects corrupted manifest JSON without throwing", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await writeFile(path.join(fixture.repoRoot, ".straight-jacket", "manifest.json"), "{not-json");

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "MANIFEST_INVALID");
  } finally {
    await fixture.cleanup();
  }
});

test("detects corrupted signature JSON without throwing", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await writeFile(path.join(fixture.repoRoot, ".straight-jacket", "manifest.sig"), "{not-json");

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "MANIFEST_SIGNATURE_INVALID");
  } finally {
    await fixture.cleanup();
  }
});

test("detects corrupted registration public verifier JSON without throwing", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await writeFile(path.join(fixture.repoRoot, ".straight-jacket", "registration-public-key.json"), "{not-json");

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "REGISTRATION_PUBLIC_KEY_INVALID");
  } finally {
    await fixture.cleanup();
  }
});

test("detects signer registry tampering without a valid registration signature", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    const signersPath = path.join(fixture.repoRoot, ".straight-jacket", "signers.json");
    const signers = JSON.parse(await readFile(signersPath, "utf8"));
    signers.signers = [];
    await writeFile(signersPath, JSON.stringify(signers, null, 2));

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "SIGNERS_SIGNATURE_INVALID");
  } finally {
    await fixture.cleanup();
  }
});

test("detects duplicate manifest paths", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    const manifestPath = path.join(fixture.repoRoot, ".straight-jacket", "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.entries.push({ ...manifest.entries[0] });
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));

    const result = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree", skipSignatureForDiagnostics: true });
    expectViolation(result, "DUPLICATE_PROTECTED_PATH", "docs/policy.md");
  } finally {
    await fixture.cleanup();
  }
});

test("detects manifest path case collisions", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await mkdir(path.join(fixture.repoRoot, "DOCS"), { recursive: true });
    await writeFile(path.join(fixture.repoRoot, "DOCS", "POLICY.md"), "# Same path different case\n");
    const manifestPath = path.join(fixture.repoRoot, ".straight-jacket", "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.entries.push({ ...manifest.entries[0], path: "DOCS/POLICY.md", name: "POLICY.md" });
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));

    const result = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree", skipSignatureForDiagnostics: true });
    expectViolation(result, "PATH_CASE_COLLISION", "DOCS/POLICY.md");
  } finally {
    await fixture.cleanup();
  }
});

test("detects absolute paths in manifest", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    const manifestPath = path.join(fixture.repoRoot, ".straight-jacket", "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.entries[0].path = path.join(fixture.repoRoot, "docs", "policy.md");
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));

    const result = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree", skipSignatureForDiagnostics: true });
    expectViolation(result, "INVALID_PATH_ABSOLUTE");
  } finally {
    await fixture.cleanup();
  }
});

test("detects parent-directory escapes in manifest", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    const manifestPath = path.join(fixture.repoRoot, ".straight-jacket", "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.entries[0].path = "../outside.md";
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));

    const result = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree", skipSignatureForDiagnostics: true });
    expectViolation(result, "INVALID_PATH_ESCAPE");
  } finally {
    await fixture.cleanup();
  }
});

test("detects protected file replaced by symlink", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    await rm(path.join(fixture.repoRoot, "docs", "policy.md"));
    await fixture.symlink("other.md", "docs/policy.md");

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree" }), "SYMLINK_NOT_ALLOWED", "docs/policy.md");
  } finally {
    await fixture.cleanup();
  }
});

test("detects hash algorithm downgrade in manifest", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    const manifestPath = path.join(fixture.repoRoot, ".straight-jacket", "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.hashAlgorithm = "md5";
    manifest.hash_algorithm = "md5";
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));

    const result = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree", skipSignatureForDiagnostics: true });
    expectViolation(result, "HASH_ALGORITHM_NOT_ALLOWED");
  } finally {
    await fixture.cleanup();
  }
});

test("detects policy downgrade in manifest", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    const manifestPath = path.join(fixture.repoRoot, ".straight-jacket", "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.policy = {
      allowSymlinks: true,
      requireHumanAuthorization: false
    };
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));

    const result = await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "working-tree", skipSignatureForDiagnostics: true });
    expectViolation(result, "POLICY_DOWNGRADE_NOT_ALLOWED");
  } finally {
    await fixture.cleanup();
  }
});

test("detects staged protected-file deletion", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    runGit(fixture.repoRoot, ["add", "."]);
    runGit(fixture.repoRoot, ["commit", "-m", "baseline"]);
    await rm(path.join(fixture.repoRoot, "docs", "policy.md"));
    runGit(fixture.repoRoot, ["add", "-A"]);

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "staged" }), "STAGED_PROTECTED_FILE_DELETED", "docs/policy.md");
  } finally {
    await fixture.cleanup();
  }
});

test("detects staged manifest tampering", async () => {
  const fixture = await createRepoFixture();
  try {
    const core = await loadCore();
    await initAndProtect(core, fixture.repoRoot);
    runGit(fixture.repoRoot, ["add", "."]);
    runGit(fixture.repoRoot, ["commit", "-m", "baseline"]);
    const manifestPath = path.join(fixture.repoRoot, ".straight-jacket", "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.entries = [];
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    runGit(fixture.repoRoot, ["add", ".straight-jacket/manifest.json"]);

    expectViolation(await core.verifyRepository({ repoRoot: fixture.repoRoot, scope: "staged" }), "STAGED_MANIFEST_SIGNATURE_INVALID");
  } finally {
    await fixture.cleanup();
  }
});
