import assert from "node:assert/strict";
import test from "node:test";

test("CLI parser maps commands, flags, and positionals without reading passwords", async () => {
  const { parseArgs } = await import("../../src/cli/parse-args.js");

  assert.deepEqual(parseArgs([]), {
    command: "help",
    positional: [],
    flags: {
      help: true
    }
  });

  assert.deepEqual(parseArgs(["--help"]), {
    command: "help",
    positional: [],
    flags: {
      help: true
    }
  });

  assert.deepEqual(parseArgs(["init", "--help"]), {
    command: "init",
    positional: [],
    flags: {
      help: true
    }
  });

  assert.deepEqual(parseArgs(["add", "docs/policy.md", "--reason", "Human-owned policy file", "--json"]), {
    command: "add",
    positional: ["docs/policy.md"],
    flags: {
      json: true,
      reason: "Human-owned policy file"
    }
  });

  assert.deepEqual(parseArgs(["verify", "--staged", "--json"]), {
    command: "verify",
    positional: [],
    flags: {
      staged: true,
      json: true
    }
  });
});

test("CLI parser rejects forbidden password source flags before dispatch", async () => {
  const { parseArgs } = await import("../../src/cli/parse-args.js");

  assert.throws(() => parseArgs(["init", "--password", "secret"]), /PASSWORD_SOURCE_NOT_ALLOWED/);
  assert.throws(() => parseArgs(["init", "--password-file", ".straight-jacket-password"]), /PASSWORD_SOURCE_NOT_ALLOWED/);
});

test("CLI output formatter writes JSON only to stdout in JSON mode", async () => {
  const { formatOutput } = await import("../../src/cli/output.js");

  const output = formatOutput({
    json: true,
    result: { ok: false, violations: [{ code: "CHECKSUM_MISMATCH" }] }
  });

  assert.equal(output.stderr, "");
  assert.equal(output.stdout, '{"ok":false,"violations":[{"code":"CHECKSUM_MISMATCH"}]}\n');
});

test("CLI help builder includes command usage and setup guidance", async () => {
  const { buildHelp } = await import("../../src/cli/help.js");

  assert.match(buildHelp(), /straight-jacket init/);
  assert.match(buildHelp(), /straight-jacket <command> --help/);
  assert.match(buildHelp(), /Passwords are never accepted through --password/);
  assert.match(buildHelp("add"), /straight-jacket add <path>/);
  assert.match(buildHelp("verify"), /--trusted-public-key-fingerprint/);
});

test("CLI exit-code mapper distinguishes success, verification failure, usage, and authorization", async () => {
  const { exitCodeForResult, exitCodeForError } = await import("../../src/cli/exit-codes.js");

  assert.equal(exitCodeForResult({ ok: true }), 0);
  assert.equal(exitCodeForResult({ ok: false, violations: [{ code: "CHECKSUM_MISMATCH" }] }), 1);
  assert.equal(exitCodeForError(Object.assign(new Error("usage"), { code: "USAGE_ERROR" })), 2);
  assert.equal(exitCodeForError(Object.assign(new Error("auth"), { code: "INVALID_PASSWORD" })), 3);
});
