import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

export const PASSWORD = "correct horse battery staple";
export const NOW = "2026-08-12T00:00:00.000Z";

export async function createRepoFixture() {
  const repoRoot = await mkdtemp(path.join(tmpdir(), "straight-jacket-"));
  runGit(repoRoot, ["init"]);
  runGit(repoRoot, ["config", "user.email", "human@example.test"]);
  runGit(repoRoot, ["config", "user.name", "Human User"]);
  await mkdir(path.join(repoRoot, "docs"), { recursive: true });
  await writeFile(path.join(repoRoot, "docs", "policy.md"), "# Policy\n\nHuman-owned text.\n");
  await writeFile(path.join(repoRoot, "docs", "other.md"), "# Other\n");

  return {
    repoRoot,
    async cleanup() {
      await rm(repoRoot, { recursive: true, force: true });
    },
    async file(relativePath) {
      return readFile(path.join(repoRoot, relativePath), "utf8");
    },
    async write(relativePath, content) {
      await mkdir(path.dirname(path.join(repoRoot, relativePath)), { recursive: true });
      await writeFile(path.join(repoRoot, relativePath), content);
    },
    async mkdir(relativePath) {
      await mkdir(path.join(repoRoot, relativePath), { recursive: true });
    },
    async symlink(target, relativePath) {
      await symlink(target, path.join(repoRoot, relativePath));
    },
    async exists(relativePath) {
      try {
        await stat(path.join(repoRoot, relativePath));
        return true;
      } catch {
        return false;
      }
    }
  };
}

export function runGit(cwd, args) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8"
  });
  assert.equal(result.status, 0, `git ${args.join(" ")} failed\n${result.stderr}`);
  return result;
}

export async function loadCore() {
  return import("../../src/index.js");
}

export async function loadMcp() {
  return import("../../src/mcp.js");
}

export function runCli(repoRoot, args, input = "") {
  return spawnSync(process.execPath, [path.join(process.cwd(), "src", "cli.js"), ...args], {
    cwd: repoRoot,
    input,
    encoding: "utf8"
  });
}

export function parseJson(stdout) {
  assert.doesNotThrow(() => JSON.parse(stdout), `stdout was not JSON:\n${stdout}`);
  return JSON.parse(stdout);
}

export async function initAndProtect(core, repoRoot, protectedPath = "docs/policy.md") {
  await core.initRepository({ repoRoot, password: PASSWORD, now: NOW });
  await core.addProtectedFile({
    repoRoot,
    path: protectedPath,
    password: PASSWORD,
    reason: "Human-owned policy file",
    now: NOW
  });
}

export function expectViolation(result, code, relativePath) {
  assert.equal(result.ok, false);
  assert.ok(Array.isArray(result.violations), "violations must be an array");
  assert.ok(
    result.violations.some((violation) => {
      return violation.code === code && (!relativePath || violation.path === relativePath);
    }),
    `expected violation ${code}${relativePath ? ` for ${relativePath}` : ""}, got ${JSON.stringify(result.violations, null, 2)}`
  );
}
