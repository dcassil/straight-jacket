import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const root = process.cwd();
const failures = [];
const requiredFiles = [
  "PRODUCT_VISION.md",
  "docs/API_CONTRACT.md",
  "docs/GUARDRAILS.md",
  "docs/TEST_STRATEGY.md",
  "docs/features/README.md",
  "docs/features/core-library.md",
  "docs/features/manifest-format.md",
  "docs/features/signing-authorization.md",
  "docs/features/git-integration.md",
  
  "docs/features/cli.md",
  "docs/features/mcp.md",
  "docs/features/hooks-ci.md",
  "docs/features/plugin-skill.md",
  "docs/features/guardrails.md",
  "docs/features/implementation-roadmap.md",
  "src/IMPLEMENTATION_SPEC.md",
  "src/core/IMPLEMENTATION_SPEC.md",
  "src/manifest/IMPLEMENTATION_SPEC.md",
  "src/signing/IMPLEMENTATION_SPEC.md",
  "src/git/IMPLEMENTATION_SPEC.md",
  "src/hooks/IMPLEMENTATION_SPEC.md",
  "src/cli/IMPLEMENTATION_SPEC.md",
  "src/mcp/IMPLEMENTATION_SPEC.md",
  "src/plugin/IMPLEMENTATION_SPEC.md",
  "src/plugin/skills/IMPLEMENTATION_SPEC.md",
  "src/plugin/mcp/IMPLEMENTATION_SPEC.md",
  "test/unit/core.test.mjs",
  "test/unit/manifest.test.mjs",
  "test/unit/signing.test.mjs",
  "test/unit/git.test.mjs",
  "test/unit/hooks.test.mjs",
  "test/unit/cli.test.mjs",
  "test/unit/mcp.test.mjs",
  "test/unit/plugin.test.mjs",
  "test/contract/core-api.contract.test.mjs",
  "test/contract/cli.contract.test.mjs",
  "test/contract/mcp.contract.test.mjs",
  "test/security/tamper-vectors.contract.test.mjs"
];

for (const file of requiredFiles) {
  if (!existsSync(path.join(root, file))) {
    failures.push(`Missing required project file: ${file}`);
  }
}

for (const file of listFiles(root)) {
  const relative = path.relative(root, file);
  if (relative.includes("node_modules")) {
    continue;
  }

  if (/(\.sj-private-key|\.straight-jacket-private-key)$/.test(relative)) {
    failures.push(`Private signing material must not be committed: ${relative}`);
  }

  const text = readFileSync(file, "utf8");
  if (/correct horse battery staple/.test(text) && !relative.startsWith("test/") && relative !== "scripts/guardrails/quality-check.mjs") {
    failures.push(`Test password fixture leaked outside tests: ${relative}`);
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log("quality guardrails ok");

function listFiles(directory) {
  if (!existsSync(directory)) {
    return [];
  }

  const files = [];
  for (const entry of readdirSync(directory)) {
    if ([".git", "node_modules", "coverage"].includes(entry)) {
      continue;
    }

    const fullPath = path.join(directory, entry);
    const stats = statSync(fullPath);
    if (stats.isDirectory()) {
      files.push(...listFiles(fullPath));
    } else if (stats.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}
