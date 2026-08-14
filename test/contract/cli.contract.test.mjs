import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import test from "node:test";
import { createRepoFixture, LOCAL_PASSWORD, MASTER_PASSWORD, parseJson, PASSWORD, runCli } from "../helpers/repo-fixture.mjs";

test("CLI help flags document setup and command-specific usage", async () => {
  const fixture = await createRepoFixture();
  try {
    const noCommand = runCli(fixture.repoRoot, []);
    assert.equal(noCommand.status, 0, noCommand.stderr);
    assert.match(noCommand.stdout, /Usage:/);
    assert.match(noCommand.stdout, /straight-jacket <command> \[options\]/);
    assert.match(noCommand.stdout, /straight-jacket init/);
    assert.match(noCommand.stdout, /straight-jacket <command> --help/);

    const longHelp = runCli(fixture.repoRoot, ["--help"]);
    assert.equal(longHelp.status, 0, longHelp.stderr);
    assert.match(longHelp.stdout, /Commands:/);
    assert.match(longHelp.stdout, /Security notes:/);

    const shortHelp = runCli(fixture.repoRoot, ["-h"]);
    assert.equal(shortHelp.status, 0, shortHelp.stderr);
    assert.match(shortHelp.stdout, /Straight Jacket protects human-owned repository files/);

    const initHelp = runCli(fixture.repoRoot, ["init", "--help"]);
    assert.equal(initHelp.status, 0, initHelp.stderr);
    assert.match(initHelp.stdout, /Usage:\n  straight-jacket init \[--json\]/);
    assert.match(initHelp.stdout, /master password and a local password/);
    assert.match(initHelp.stdout, /Run this from the project root/);

    const initShortHelp = runCli(fixture.repoRoot, ["init", "-h"]);
    assert.equal(initShortHelp.status, 0, initShortHelp.stderr);
    assert.match(initShortHelp.stdout, /straight-jacket init \[--json\]/);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI init creates repo metadata and returns stable JSON with CI key guidance", async () => {
  const fixture = await createRepoFixture();
  try {
    const result = runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`);

    assert.equal(result.status, 0, result.stderr);
    const body = parseJson(result.stdout);
    assert.equal(body.ok, true);
    assert.match(body.fingerprint, /^sha256:[a-f0-9]+$/);
    assert.equal(await fixture.exists(".straight-jacket/manifest.json"), true);
    assert.equal(await fixture.exists(".straight-jacket/manifest.sig"), true);
    assert.equal(await fixture.exists(".straight-jacket/signers.json"), true);
    assert.equal(await fixture.exists(".straight-jacket/signers.sig"), true);
    assert.equal(await fixture.exists(".straight-jacket/registration-public-key.json"), true);
    assert.equal(await fixture.exists(".straight-jacket/registration-key.enc.json"), true);
    assert.equal(await fixture.exists(".straight-jacket/ci-proof.json"), true);
    assert.equal(body.ci.secretName, "STRAIGHT_JACKET_CI_KEY");
    assert.match(body.ci.ciKey, /^sjci_v1_/);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI init accepts distinct master and local passwords", async () => {
  const fixture = await createRepoFixture();
  try {
    const init = runCli(
      fixture.repoRoot,
      ["init", "--json"],
      `${MASTER_PASSWORD}\n${MASTER_PASSWORD}\n${LOCAL_PASSWORD}\n${LOCAL_PASSWORD}\n`
    );
    assert.equal(init.status, 0, init.stderr);

    const masterAdd = runCli(
      fixture.repoRoot,
      ["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"],
      `${MASTER_PASSWORD}\n`
    );
    assert.notEqual(masterAdd.status, 0);
    assert.match(masterAdd.stderr + masterAdd.stdout, /INVALID_PASSWORD/);

    const localAdd = runCli(
      fixture.repoRoot,
      ["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"],
      `${LOCAL_PASSWORD}\n`
    );
    assert.equal(localAdd.status, 0, localAdd.stderr);
    assert.equal(parseJson(localAdd.stdout).ok, true);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI setup check reports missing local signer until setup registers one", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(
      runCli(fixture.repoRoot, ["init", "--json"], `${MASTER_PASSWORD}\n${MASTER_PASSWORD}\n${LOCAL_PASSWORD}\n${LOCAL_PASSWORD}\n`).status,
      0
    );
    assert.equal(
      runCli(fixture.repoRoot, ["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"], `${LOCAL_PASSWORD}\n`).status,
      0
    );
    await rm(`${fixture.repoRoot}/.straight-jacket/local`, { recursive: true, force: true });

    const checkBefore = runCli(fixture.repoRoot, ["setup", "--check", "--json"]);
    assert.notEqual(checkBefore.status, 0);
    assert.match(checkBefore.stdout, /LOCAL_SIGNER_MISSING/);

    const setup = runCli(
      fixture.repoRoot,
      ["setup", "--json"],
      `${MASTER_PASSWORD}\nfresh local password\nfresh local password\n`
    );
    assert.equal(setup.status, 0, setup.stderr);
    assert.equal(parseJson(setup.stdout).registered, true);
    assert.equal(parseJson(setup.stdout).ci.secretName, "STRAIGHT_JACKET_CI_KEY");

    const checkAfter = runCli(fixture.repoRoot, ["setup", "--check", "--json"]);
    assert.equal(checkAfter.status, 0, checkAfter.stderr);
    assert.equal(parseJson(checkAfter.stdout).ok, true);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI add/list/verify expose expected machine-readable contract", async () => {
  const fixture = await createRepoFixture();
  try {
    const init = runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`);
    assert.equal(init.status, 0);
    const initBody = parseJson(init.stdout);

    const add = runCli(
      fixture.repoRoot,
      ["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"],
      `${PASSWORD}\n`
    );
    assert.equal(add.status, 0, add.stderr);
    const addBody = parseJson(add.stdout);
    assert.equal(addBody.ok, true);
    assert.equal(addBody.entry.path, "docs/policy.md");

    const list = runCli(fixture.repoRoot, ["list", "--json"]);
    assert.equal(list.status, 0, list.stderr);
    const listBody = parseJson(list.stdout);
    assert.equal(listBody.ok, true);
    assert.equal(listBody.entries.length, 1);
    assert.equal(listBody.entries[0].path, "docs/policy.md");

    const verify = runCli(fixture.repoRoot, ["verify", "--json"]);
    assert.equal(verify.status, 0, verify.stderr);
    assert.deepEqual(parseJson(verify.stdout), { ok: true, checked: 1, violations: [] });

    const ciVerify = runCli(fixture.repoRoot, ["verify", "--ci-key", initBody.ci.ciKey, "--json"]);
    assert.equal(ciVerify.status, 0, ciVerify.stderr);
    assert.deepEqual(parseJson(ciVerify.stdout), { ok: true, checked: 1, violations: [] });

    const missingSecretVerify = runCli(fixture.repoRoot, ["verify", "--ci-key", "", "--json"]);
    assert.notEqual(missingSecretVerify.status, 0);
    assert.equal(parseJson(missingSecretVerify.stdout).violations[0].code, "CI_KEY_INVALID");
  } finally {
    await fixture.cleanup();
  }
});

test("CLI add accepts shell-expanded path lists and remove accepts registered path patterns", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);
    await fixture.write("tools/pre-commit-alpha", "#!/bin/sh\n");
    await fixture.write("tools/pre-commit-beta", "#!/bin/sh\n");

    const add = runCli(
      fixture.repoRoot,
      ["add", "tools/pre-commit-alpha", "tools/pre-commit-beta", "--reason", "Hook scripts", "--json"],
      `${PASSWORD}\n`
    );

    assert.equal(add.status, 0, add.stderr);
    const addBody = parseJson(add.stdout);
    assert.equal(addBody.ok, true);
    assert.deepEqual(addBody.entries.map((entry) => entry.path), [
      "tools/pre-commit-alpha",
      "tools/pre-commit-beta"
    ]);

    const remove = runCli(fixture.repoRoot, ["remove", "tools/pre-commit-*", "--json"], `${PASSWORD}\n`);

    assert.equal(remove.status, 0, remove.stderr);
    assert.deepEqual(parseJson(remove.stdout), {
      ok: true,
      removedPaths: [
        "tools/pre-commit-alpha",
        "tools/pre-commit-beta"
      ]
    });

    const verify = runCli(fixture.repoRoot, ["verify", "--json"]);
    assert.equal(verify.status, 0, verify.stderr);
    assert.deepEqual(parseJson(verify.stdout), { ok: true, checked: 0, violations: [] });
  } finally {
    await fixture.cleanup();
  }
});

test("CLI verification exits non-zero and emits stable violation JSON when protected content changes", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);
    assert.equal(
      runCli(fixture.repoRoot, ["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"], `${PASSWORD}\n`).status,
      0
    );
    await fixture.write("docs/policy.md", "# Policy\n\nAI changed this.\n");

    const verify = runCli(fixture.repoRoot, ["verify", "--json"]);

    assert.notEqual(verify.status, 0);
    const body = parseJson(verify.stdout);
    assert.equal(body.ok, false);
    assert.equal(body.violations[0].code, "CHECKSUM_MISMATCH");
    assert.equal(body.violations[0].path, "docs/policy.md");
    assert.match(body.violations[0].expected, /^sha256:/);
    assert.match(body.violations[0].actual, /^sha256:/);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI verification emits actionable human output when protected content changes", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);
    assert.equal(
      runCli(fixture.repoRoot, ["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"], `${PASSWORD}\n`).status,
      0
    );
    await fixture.write("docs/policy.md", "# Policy\n\nAI changed this.\n");

    const verify = runCli(fixture.repoRoot, ["verify"]);

    assert.notEqual(verify.status, 0);
    assert.match(verify.stdout, /Straight Jacket verification failed/);
    assert.match(verify.stdout, /Locked files:\n- docs\/policy\.md/);
    assert.match(verify.stdout, /straight-jacket update docs\/policy\.md/);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI verification warn mode reports violations without a failing exit", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);
    assert.equal(
      runCli(fixture.repoRoot, ["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"], `${PASSWORD}\n`).status,
      0
    );
    await fixture.write("docs/policy.md", "# Policy\n\nAI changed this.\n");

    const verify = runCli(fixture.repoRoot, ["verify", "--warn"]);

    assert.equal(verify.status, 0, verify.stderr);
    assert.match(verify.stdout, /Straight Jacket verification failed/);
    assert.match(verify.stdout, /straight-jacket update docs\/policy\.md/);
    assert.match(verify.stdout, /before a PR to a protected branch will pass the locked changes must be approved/);

    const verifyJson = runCli(fixture.repoRoot, ["verify", "--warn", "--json"]);
    assert.equal(verifyJson.status, 0, verifyJson.stderr);
    const body = parseJson(verifyJson.stdout);
    assert.equal(body.ok, false);
    assert.equal(body.warn, true);
    assert.equal(body.violations[0].code, "CHECKSUM_MISMATCH");
  } finally {
    await fixture.cleanup();
  }
});

test("CLI verification emits one copy-pasteable update command for multiple approved changes", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);
    assert.equal(
      runCli(fixture.repoRoot, ["add", "docs/policy.md", "docs/other.md", "--reason", "Human-owned files", "--json"], `${PASSWORD}\n`).status,
      0
    );
    await fixture.write("docs/policy.md", "# Policy\n\nAI changed this.\n");
    await fixture.write("docs/other.md", "# Other\n\nAI changed this too.\n");

    const verify = runCli(fixture.repoRoot, ["verify"]);

    assert.notEqual(verify.status, 0);
    assert.match(verify.stdout, /straight-jacket update docs\/other\.md docs\/policy\.md/);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI status reports hook health without claiming local hooks are the strong security boundary", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);

    const beforeHook = runCli(fixture.repoRoot, ["status", "--json"]);
    assert.equal(beforeHook.status, 0, beforeHook.stderr);
    const beforeBody = parseJson(beforeHook.stdout);
    assert.equal(beforeBody.ok, true);
    assert.equal(beforeBody.hook.installed, false);
    assert.equal(beforeBody.enforcement.localHookAdvisory, true);

    const install = runCli(fixture.repoRoot, ["install-hook", "--json"]);
    assert.equal(install.status, 0, install.stderr);
    assert.equal(parseJson(install.stdout).ok, true);

    const afterHook = parseJson(runCli(fixture.repoRoot, ["status", "--json"]).stdout);
    assert.equal(afterHook.hook.installed, true);
    assert.equal(afterHook.enforcement.requiresExternalVerifierForStrongMode, true);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI update accepts changed protected content only after interactive authorization", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);
    assert.equal(
      runCli(fixture.repoRoot, ["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"], `${PASSWORD}\n`).status,
      0
    );
    await fixture.write("docs/policy.md", "# Policy\n\nHuman-approved replacement.\n");

    const update = runCli(fixture.repoRoot, ["update", "docs/policy.md", "--json"], `${PASSWORD}\n`);

    assert.equal(update.status, 0, update.stderr);
    const body = parseJson(update.stdout);
    assert.equal(body.ok, true);
    assert.equal(body.entry.path, "docs/policy.md");
    assert.match(body.entry.checksum, /^sha256:/);
    assert.equal("entries" in body, false);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI update accepts multiple changed protected files with one authorization", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);
    assert.equal(
      runCli(fixture.repoRoot, ["add", "docs/policy.md", "docs/other.md", "--reason", "Human-owned files", "--json"], `${PASSWORD}\n`).status,
      0
    );
    await fixture.write("docs/policy.md", "# Policy\n\nHuman-approved replacement.\n");
    await fixture.write("docs/other.md", "# Other\n\nHuman-approved replacement.\n");

    const update = runCli(fixture.repoRoot, ["update", "docs/policy.md", "docs/other.md", "--json"], `${PASSWORD}\n`);

    assert.equal(update.status, 0, update.stderr);
    const body = parseJson(update.stdout);
    assert.equal(body.ok, true);
    assert.deepEqual(body.entries.map((entry) => entry.path), ["docs/policy.md", "docs/other.md"]);

    const verify = runCli(fixture.repoRoot, ["verify", "--json"]);
    assert.equal(verify.status, 0, verify.stderr);
    assert.deepEqual(parseJson(verify.stdout), { ok: true, checked: 2, violations: [] });
  } finally {
    await fixture.cleanup();
  }
});

test("CLI remove deletes a protected entry only after interactive authorization", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);
    assert.equal(
      runCli(fixture.repoRoot, ["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"], `${PASSWORD}\n`).status,
      0
    );

    const remove = runCli(fixture.repoRoot, ["remove", "docs/policy.md", "--json"], `${PASSWORD}\n`);

    assert.equal(remove.status, 0, remove.stderr);
    assert.deepEqual(parseJson(remove.stdout), { ok: true, removedPath: "docs/policy.md" });
  } finally {
    await fixture.cleanup();
  }
});

test("CLI rename authorizes a protected path change explicitly", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);
    assert.equal(
      runCli(fixture.repoRoot, ["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"], `${PASSWORD}\n`).status,
      0
    );
    await fixture.write("docs/policy-renamed.md", await fixture.file("docs/policy.md"));

    const rename = runCli(fixture.repoRoot, ["rename", "docs/policy.md", "docs/policy-renamed.md", "--json"], `${PASSWORD}\n`);

    assert.equal(rename.status, 0, rename.stderr);
    const body = parseJson(rename.stdout);
    assert.equal(body.ok, true);
    assert.equal(body.from, "docs/policy.md");
    assert.equal(body.to, "docs/policy-renamed.md");
  } finally {
    await fixture.cleanup();
  }
});

test("CLI install-ci writes a verifier workflow with CI key guidance", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);

    const install = runCli(fixture.repoRoot, ["install-ci", "--provider", "github-actions", "--json"]);

    assert.equal(install.status, 0, install.stderr);
    const body = parseJson(install.stdout);
    assert.equal(body.ok, true);
    assert.equal(body.provider, "github-actions");
    assert.equal(body.path, ".github/workflows/straight-jacket.yml");
    assert.equal(await fixture.exists(".github/workflows/straight-jacket.yml"), true);
    assert.doesNotMatch(await fixture.file(".github/workflows/straight-jacket.yml"), /straight-jacket verify .*--json/);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI mutating commands reject non-interactive password injection flags and repo-file password sources", async () => {
  const fixture = await createRepoFixture();
  try {
    const withPasswordFlag = runCli(fixture.repoRoot, ["init", "--password", PASSWORD, "--json"]);
    assert.notEqual(withPasswordFlag.status, 0);
    assert.match(withPasswordFlag.stderr + withPasswordFlag.stdout, /PASSWORD_SOURCE_NOT_ALLOWED|interactive/i);

    await fixture.write(".straight-jacket-password", PASSWORD);
    const withPasswordFile = runCli(fixture.repoRoot, ["init", "--password-file", ".straight-jacket-password", "--json"]);
    assert.notEqual(withPasswordFile.status, 0);
    assert.match(withPasswordFile.stderr + withPasswordFile.stdout, /PASSWORD_SOURCE_NOT_ALLOWED|interactive/i);
  } finally {
    await fixture.cleanup();
  }
});
