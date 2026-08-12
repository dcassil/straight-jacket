import assert from "node:assert/strict";
import test from "node:test";
import { createRepoFixture, parseJson, PASSWORD, runCli } from "../helpers/repo-fixture.mjs";

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
    assert.match(initHelp.stdout, /Prompts for a human password twice/);
    assert.match(initHelp.stdout, /Run this from the project root/);

    const initShortHelp = runCli(fixture.repoRoot, ["init", "-h"]);
    assert.equal(initShortHelp.status, 0, initShortHelp.stderr);
    assert.match(initShortHelp.stdout, /straight-jacket init \[--json\]/);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI init creates repo metadata and returns stable JSON with public verifier fingerprint", async () => {
  const fixture = await createRepoFixture();
  try {
    const result = runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`);

    assert.equal(result.status, 0, result.stderr);
    const body = parseJson(result.stdout);
    assert.equal(body.ok, true);
    assert.match(body.fingerprint, /^sha256:[a-f0-9]+$/);
    assert.equal(await fixture.exists(".straight-jacket/manifest.json"), true);
    assert.equal(await fixture.exists(".straight-jacket/manifest.sig"), true);
    assert.equal(await fixture.exists(".straight-jacket/public-key.json"), true);
  } finally {
    await fixture.cleanup();
  }
});

test("CLI add/list/verify expose expected machine-readable contract", async () => {
  const fixture = await createRepoFixture();
  try {
    assert.equal(runCli(fixture.repoRoot, ["init", "--json"], `${PASSWORD}\n${PASSWORD}\n`).status, 0);

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

test("CLI install-ci writes a verifier workflow with external fingerprint guidance", async () => {
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
