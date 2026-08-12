import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

function runGuardrail(script) {
  const result = spawnSync(process.execPath, [script], {
    cwd: process.cwd(),
    encoding: "utf8"
  });
  assert.equal(result.status, 0, `${script} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
}

test("boundary guardrail script passes", () => {
  runGuardrail("scripts/guardrails/boundary-check.mjs");
});

test("tamper-vector coverage guardrail script passes", () => {
  runGuardrail("scripts/guardrails/coverage-check.mjs");
});

test("quality guardrail script passes", () => {
  runGuardrail("scripts/guardrails/quality-check.mjs");
});
