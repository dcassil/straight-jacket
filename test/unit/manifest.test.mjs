import assert from "node:assert/strict";
import test from "node:test";

test("manifest canonical JSON sorts object keys recursively without changing array order", async () => {
  const { canonicalizeJson } = await import("../../src/manifest/canonical-json.js");

  const canonical = canonicalizeJson({
    z: 1,
    a: {
      d: true,
      b: "value"
    },
    entries: [
      { path: "b.md", checksum: "sha256:b" },
      { checksum: "sha256:a", path: "a.md" }
    ]
  });

  assert.equal(
    canonical,
    '{"a":{"b":"value","d":true},"entries":[{"checksum":"sha256:b","path":"b.md"},{"checksum":"sha256:a","path":"a.md"}],"z":1}'
  );
});

test("manifest canonical JSON rejects non-deterministic values", async () => {
  const { canonicalizeJson } = await import("../../src/manifest/canonical-json.js");

  assert.throws(() => canonicalizeJson({ value: undefined }), /CANONICAL_JSON_UNSUPPORTED_VALUE/);
  assert.throws(() => canonicalizeJson({ value: Number.NaN }), /CANONICAL_JSON_UNSUPPORTED_VALUE/);
  assert.throws(() => canonicalizeJson({ value: Infinity }), /CANONICAL_JSON_UNSUPPORTED_VALUE/);
});

test("manifest validation accepts the canonical MVP manifest shape", async () => {
  const { validateManifestShape } = await import("../../src/manifest/validation.js");

  const violations = validateManifestShape({
    version: 1,
    repoId: "sha256:" + "a".repeat(64),
    hashAlgorithm: "sha256",
    signatureAlgorithm: "ed25519",
    keyId: "sha256:" + "b".repeat(64),
    policy: {
      allowSymlinks: false,
      requireHumanAuthorization: true,
      failClosed: true
    },
    entries: []
  });

  assert.deepEqual(violations, []);
});

test("manifest validation rejects duplicate paths, case collisions, algorithm downgrade, and policy downgrade", async () => {
  const { validateManifestShape } = await import("../../src/manifest/validation.js");

  const baseEntry = {
    path: "docs/policy.md",
    name: "policy.md",
    checksum: "sha256:" + "c".repeat(64),
    size: 12,
    registeredAt: "2026-08-12T00:00:00.000Z",
    reason: "Human-owned policy file"
  };

  const violations = validateManifestShape({
    version: 1,
    repoId: "sha256:" + "a".repeat(64),
    hashAlgorithm: "md5",
    signatureAlgorithm: "ed25519",
    keyId: "sha256:" + "b".repeat(64),
    policy: {
      allowSymlinks: true,
      requireHumanAuthorization: false,
      failClosed: false
    },
    entries: [
      baseEntry,
      { ...baseEntry },
      { ...baseEntry, path: "DOCS/POLICY.md", name: "POLICY.md" }
    ]
  });

  assert.deepEqual(
    violations.map((violation) => violation.code).sort(),
    [
      "DUPLICATE_PROTECTED_PATH",
      "HASH_ALGORITHM_NOT_ALLOWED",
      "PATH_CASE_COLLISION",
      "POLICY_DOWNGRADE_NOT_ALLOWED"
    ]
  );
});

test("manifest entries are sorted deterministically by normalized path", async () => {
  const { sortEntries } = await import("../../src/manifest/entries.js");

  assert.deepEqual(
    sortEntries([
      { path: "z-last.md" },
      { path: "Docs/B.md" },
      { path: "docs/a.md" }
    ]).map((entry) => entry.path),
    ["docs/a.md", "Docs/B.md", "z-last.md"]
  );
});
