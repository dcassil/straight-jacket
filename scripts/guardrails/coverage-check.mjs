import { readFileSync } from "node:fs";

const tamperTest = readFileSync("test/security/tamper-vectors.contract.test.mjs", "utf8");
const requiredVectors = [
  "protected file content modification",
  "protected file deletion",
  "protected file move or rename",
  "direct manifest checksum editing",
  "manifest deletion",
  "signature deletion",
  "public verifier deletion",
  "public verifier replacement",
  "duplicate manifest paths",
  "manifest path case collisions",
  "absolute paths in manifest",
  "parent-directory escapes in manifest",
  "protected file replaced by symlink",
  "hash algorithm downgrade",
  "policy downgrade",
  "staged protected-file deletion",
  "staged manifest tampering"
];

const missing = requiredVectors.filter((vector) => !tamperTest.includes(vector));

if (missing.length > 0) {
  console.error("Missing tamper-vector contract coverage:");
  for (const vector of missing) {
    console.error(`- ${vector}`);
  }
  process.exit(1);
}

console.log("tamper-vector coverage guardrails ok");
