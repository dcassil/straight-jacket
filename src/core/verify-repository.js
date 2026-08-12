import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { canonicalizeJson } from "../manifest/canonical-json.js";
import { readManifest, readPublicKey, readSignature } from "../manifest/read-write.js";
import { validateManifestShape } from "../manifest/validation.js";
import { fingerprintPublicKey } from "../signing/keys.js";
import { verifyPayloadSignature } from "../signing/signatures.js";
import { createViolation } from "./violations.js";
import { buildVerificationResult } from "./verification-result.js";

export async function verifyRepository({ repoRoot, scope = "working-tree", trustedPublicKeyFingerprint, skipSignatureForDiagnostics = false } = {}) {
  if (scope !== "working-tree") {
    return buildVerificationResult({ checked: 0, violations: [] });
  }

  const violations = [];
  const manifest = await readJsonOrViolation(repoRoot, "manifest");
  const signature = await readJsonOrViolation(repoRoot, "signature");
  const publicKey = await readJsonOrViolation(repoRoot, "publicKey");

  if (manifest.violation) {
    violations.push(manifest.violation);
  }
  if (signature.violation) {
    violations.push(signature.violation);
  }
  if (publicKey.violation) {
    violations.push(publicKey.violation);
  }

  if (violations.length > 0) {
    return buildVerificationResult({ checked: 0, violations });
  }

  if (trustedPublicKeyFingerprint && fingerprintPublicKey(publicKey.value) !== trustedPublicKeyFingerprint) {
    violations.push(createViolation("PUBLIC_KEY_FINGERPRINT_MISMATCH", {
      expected: trustedPublicKeyFingerprint,
      actual: fingerprintPublicKey(publicKey.value)
    }));
  }

  const manifestViolations = validateManifestShape(manifest.value).map((violation) => createViolation(violation.code, violation));
  violations.push(...manifestViolations);

  if (!skipSignatureForDiagnostics) {
    const signatureValid = await verifyPayloadSignature({
      payload: canonicalizeJson(manifest.value),
      signature: signature.value,
      publicKey: publicKey.value
    });
    if (!signatureValid) {
      violations.push(createViolation("MANIFEST_SIGNATURE_INVALID"));
    }
  }

  if (violations.length === 0) {
    violations.push(...await verifyWorkingTreeEntries({ repoRoot, entries: manifest.value.entries }));
  }

  return buildVerificationResult({
    checked: Array.isArray(manifest.value?.entries) ? manifest.value.entries.length : 0,
    violations
  });
}

async function verifyWorkingTreeEntries({ repoRoot, entries }) {
  const violations = [];

  for (const entry of entries) {
    try {
      const filePath = new URL(entry.path, `file://${repoRoot}/`);
      const stats = await lstat(filePath);
      if (stats.isSymbolicLink()) {
        violations.push(createViolation("SYMLINK_NOT_ALLOWED", { path: entry.path }));
        continue;
      }
      const content = await readFile(filePath);
      const actual = `sha256:${createHash("sha256").update(content).digest("hex")}`;
      if (actual !== entry.checksum) {
        violations.push(createViolation("CHECKSUM_MISMATCH", {
          path: entry.path,
          expected: entry.checksum,
          actual
        }));
      }
    } catch (error) {
      if (error.code === "ENOENT") {
        violations.push(createViolation("PROTECTED_FILE_MISSING", { path: entry.path }));
        continue;
      }
      throw error;
    }
  }

  return violations;
}

async function readJsonOrViolation(repoRoot, kind) {
  try {
    if (kind === "manifest") {
      return { value: await readManifest(repoRoot) };
    }
    if (kind === "signature") {
      return { value: await readSignature(repoRoot) };
    }
    return { value: await readPublicKey(repoRoot) };
  } catch (error) {
    if (error.code === "ENOENT") {
      return { violation: createViolation(missingCodeForKind(kind)) };
    }
    throw error;
  }
}

function missingCodeForKind(kind) {
  if (kind === "manifest") {
    return "MANIFEST_MISSING";
  }
  if (kind === "signature") {
    return "MANIFEST_SIGNATURE_MISSING";
  }
  return "PUBLIC_KEY_MISSING";
}
