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

  assert.deepEqual(parseArgs(["verify", "--ci-key", "sjci_v1_example", "--json"]), {
    command: "verify",
    positional: [],
    flags: {
      ciKey: "sjci_v1_example",
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

test("CLI output formatter gives actionable human verification failures", async () => {
  const { formatOutput } = await import("../../src/cli/output.js");

  const output = formatOutput({
    json: false,
    result: {
      ok: false,
      violations: [{
        code: "CHECKSUM_MISMATCH",
        path: "docs/policy.md",
        message: "docs/policy.md checksum changed"
      }]
    }
  });

  assert.equal(output.stderr, "");
  assert.match(output.stdout, /Straight Jacket verification failed/);
  assert.match(output.stdout, /Locked files:\n- docs\/policy\.md/);
  assert.match(output.stdout, /CHECKSUM_MISMATCH docs\/policy\.md/);
  assert.match(output.stdout, /straight-jacket update docs\/policy\.md/);
});

test("CLI output formatter groups approved checksum updates into one command", async () => {
  const { formatOutput } = await import("../../src/cli/output.js");

  const output = formatOutput({
    json: false,
    result: {
      ok: false,
      violations: [
        {
          code: "CHECKSUM_MISMATCH",
          path: "docs/policy.md",
          message: "docs/policy.md checksum changed"
        },
        {
          code: "CHECKSUM_MISMATCH",
          path: "prompts/system prompt.md",
          message: "prompts/system prompt.md checksum changed"
        }
      ]
    }
  });

  assert.match(output.stdout, /straight-jacket update docs\/policy\.md 'prompts\/system prompt\.md'/);
});

test("CLI output formatter suggests remove and rename commands when applicable", async () => {
  const { formatOutput } = await import("../../src/cli/output.js");

  const output = formatOutput({
    json: false,
    result: {
      ok: false,
      violations: [
        {
          code: "PROTECTED_FILE_MISSING",
          path: "docs/missing.md",
          message: "docs/missing.md is missing"
        },
        {
          code: "LIKELY_RENAME_OR_MOVE",
          path: "docs/new.md",
          expectedPath: "docs/old.md",
          message: "docs/new.md appears to contain a protected file moved from another path"
        }
      ]
    }
  });

  assert.match(output.stdout, /- docs\/missing\.md/);
  assert.match(output.stdout, /- docs\/old\.md/);
  assert.match(output.stdout, /straight-jacket remove docs\/missing\.md/);
  assert.match(output.stdout, /straight-jacket rename docs\/old\.md docs\/new\.md/);
});

test("CLI output formatter prints CI setup instructions after initialization", async () => {
  const { formatOutput } = await import("../../src/cli/output.js");

  const output = formatOutput({
    json: false,
    result: {
      ok: true,
      ci: {
        secretName: "STRAIGHT_JACKET_CI_KEY",
        ciKey: "sjci_v1_example",
        warning: "Never give an AI agent your master password."
      }
    }
  });

  assert.match(output.stdout, /Create a repository secret named STRAIGHT_JACKET_CI_KEY/);
  assert.match(output.stdout, /sjci_v1_example/);
  assert.match(output.stdout, /Never give an AI agent your master password/);
});

test("CLI help builder includes command usage and setup guidance", async () => {
  const { buildHelp } = await import("../../src/cli/help.js");

  assert.match(buildHelp(), /straight-jacket init/);
  assert.match(buildHelp(), /straight-jacket <command> --help/);
  assert.match(buildHelp(), /Passwords are never accepted through --password/);
  assert.match(buildHelp("add"), /straight-jacket add <path-or-pattern>\.\.\./);
  assert.match(buildHelp("add"), /Directory checksums are not supported yet/);
  assert.match(buildHelp("remove"), /straight-jacket remove <path-or-pattern>\.\.\./);
  assert.match(buildHelp("verify"), /--ci-key/);
});

test("CLI exit-code mapper distinguishes success, verification failure, usage, and authorization", async () => {
  const { exitCodeForResult, exitCodeForError } = await import("../../src/cli/exit-codes.js");

  assert.equal(exitCodeForResult({ ok: true }), 0);
  assert.equal(exitCodeForResult({ ok: false, violations: [{ code: "CHECKSUM_MISMATCH" }] }), 1);
  assert.equal(exitCodeForError(Object.assign(new Error("usage"), { code: "USAGE_ERROR" })), 2);
  assert.equal(exitCodeForError(Object.assign(new Error("auth"), { code: "INVALID_PASSWORD" })), 3);
});
