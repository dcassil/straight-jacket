import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { resolveRepoPath } from "../git/paths.js";
import { scanForChecksum } from "../git/scan.js";
import { getStagedChanges, readStagedFile } from "../git/staged.js";
import { canonicalizeJson } from "../manifest/canonical-json.js";
import {
  MANIFEST_PATH,
  REGISTRATION_PUBLIC_KEY_PATH,
  SIGNATURE_PATH,
  SIGNERS_PATH,
  SIGNERS_SIGNATURE_PATH,
  readManifest,
  readRegistrationPublicKey,
  readSignature,
  readSigners,
  readSignersSignature
} from "../manifest/read-write.js";
import { validateManifestShape } from "../manifest/validation.js";
import { fingerprintPublicKey } from "../signing/keys.js";
import { verifyPayloadSignature } from "../signing/signatures.js";
import { findActiveSigner, publicKeyFromSigner, validateSignerRegistry } from "../signing/signer-registry.js";
import { createViolation } from "./violations.js";
import { buildVerificationResult } from "./verification-result.js";

const METADATA_PATHS = new Set([
  MANIFEST_PATH,
  SIGNATURE_PATH,
  SIGNERS_PATH,
  SIGNERS_SIGNATURE_PATH,
  REGISTRATION_PUBLIC_KEY_PATH
]);

export async function verifyRepository({ repoRoot, scope = "working-tree", trustedPublicKeyFingerprint, skipSignatureForDiagnostics = false } = {}) {
  if (scope !== "working-tree") {
    if (scope === "staged") {
      return verifyStagedScope({ repoRoot });
    }
    return buildVerificationResult({ checked: 0, violations: [] });
  }

  const violations = [];
  const metadata = await readMetadataOrViolations(repoRoot);
  const { manifest, signature, signers, signersSignature, registrationPublicKey } = metadata;

  violations.push(...metadata.violations);

  if (violations.length > 0) {
    return buildVerificationResult({ checked: 0, violations });
  }

  if (trustedPublicKeyFingerprint) {
    const actualFingerprint = fingerprintPublicKeyOrNull(registrationPublicKey.value);
    if (actualFingerprint === null) {
      violations.push(createViolation("REGISTRATION_PUBLIC_KEY_INVALID"));
    } else if (actualFingerprint !== trustedPublicKeyFingerprint) {
      violations.push(createViolation("PUBLIC_KEY_FINGERPRINT_MISMATCH", {
        expected: trustedPublicKeyFingerprint,
        actual: actualFingerprint
      }));
    }
  }

  const manifestViolations = validateManifestShape(manifest.value).map((violation) => createViolation(violation.code, violation));
  violations.push(...manifestViolations);
  const signerViolations = validateSignerRegistry(signers.value).map((violation) => createViolation(violation.code, violation));
  violations.push(...signerViolations);

  if (violations.length === 0) {
    const signersSignatureValid = await verifyPayloadSignature({
      payload: canonicalizeJson(signers.value),
      signature: signersSignature.value,
      publicKey: registrationPublicKey.value
    });
    if (!signersSignatureValid) {
      violations.push(createViolation("SIGNERS_SIGNATURE_INVALID"));
    }
  }

  if (!skipSignatureForDiagnostics && violations.length === 0) {
    const signer = findActiveSigner(signers.value, signature.value.keyId ?? manifest.value.keyId);
    if (!signer || manifest.value.keyId !== signer.keyId) {
      violations.push(createViolation("MANIFEST_SIGNER_NOT_REGISTERED"));
    } else {
      const signatureValid = await verifyPayloadSignature({
        payload: canonicalizeJson(manifest.value),
        signature: signature.value,
        publicKey: publicKeyFromSigner(signer)
      });
      if (!signatureValid) {
        violations.push(createViolation("MANIFEST_SIGNATURE_INVALID"));
      }
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

async function verifyStagedScope({ repoRoot }) {
  const workingMetadata = await readMetadataOrViolations(repoRoot);
  if (workingMetadata.manifest?.violation) {
    return buildVerificationResult({ checked: 0, violations: [workingMetadata.manifest.violation] });
  }

  const changes = await getStagedChanges(repoRoot);
  const violations = [];
  const stagedMetadata = await readStagedMetadataOrViolations(repoRoot);
  const manifestForProtectedPaths = stagedMetadata.manifest?.value ?? workingMetadata.manifest.value;
  const protectedPaths = new Set(manifestForProtectedPaths.entries.map((entry) => entry.path));

  for (const change of changes) {
    if ((change.status === "deleted" && protectedPaths.has(change.path)) ||
      (change.status === "renamed" && protectedPaths.has(change.oldPath))) {
      violations.push(createViolation("STAGED_PROTECTED_FILE_DELETED", {
        path: change.oldPath ?? change.path
      }));
    }
  }

  if (changes.some((change) => METADATA_PATHS.has(change.path) || METADATA_PATHS.has(change.oldPath))) {
    const metadataViolations = await verifyMetadataValues(stagedMetadata);
    if (metadataViolations.length > 0) {
      violations.push(createViolation("STAGED_MANIFEST_SIGNATURE_INVALID", {
        path: MANIFEST_PATH
      }));
    }
  }

  return buildVerificationResult({
    checked: manifestForProtectedPaths.entries.length,
    violations
  });
}

async function verifyWorkingTreeEntries({ repoRoot, entries }) {
  const violations = [];

  for (const entry of entries) {
    try {
      const filePath = resolveRepoPath(repoRoot, entry.path);
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
        const likelyMoves = await scanForChecksum(repoRoot, entry.checksum, {
          ignoredDirectories: [".straight-jacket"]
        });
        for (const likelyMove of likelyMoves.filter((match) => match.path !== entry.path)) {
          violations.push(createViolation("LIKELY_RENAME_OR_MOVE", { path: likelyMove.path, expectedPath: entry.path }));
        }
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
    if (kind === "signers") {
      return { value: await readSigners(repoRoot) };
    }
    if (kind === "signersSignature") {
      return { value: await readSignersSignature(repoRoot) };
    }
    return { value: await readRegistrationPublicKey(repoRoot) };
  } catch (error) {
    if (error.code === "ENOENT") {
      return { violation: createViolation(missingCodeForKind(kind)) };
    }
    if (error instanceof SyntaxError) {
      return { violation: createViolation(invalidCodeForKind(kind)) };
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
  if (kind === "signers") {
    return "SIGNERS_MISSING";
  }
  if (kind === "signersSignature") {
    return "SIGNERS_SIGNATURE_MISSING";
  }
  return "REGISTRATION_PUBLIC_KEY_MISSING";
}

function invalidCodeForKind(kind) {
  if (kind === "manifest") {
    return "MANIFEST_INVALID";
  }
  if (kind === "signature") {
    return "MANIFEST_SIGNATURE_INVALID";
  }
  if (kind === "signers") {
    return "SIGNERS_INVALID";
  }
  if (kind === "signersSignature") {
    return "SIGNERS_SIGNATURE_INVALID";
  }
  return "REGISTRATION_PUBLIC_KEY_INVALID";
}

function fingerprintPublicKeyOrNull(publicKey) {
  try {
    return fingerprintPublicKey(publicKey);
  } catch {
    return null;
  }
}

function parseJsonOrNull(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function readMetadataOrViolations(repoRoot) {
  const [manifest, signature, signers, signersSignature, registrationPublicKey] = await Promise.all([
    readJsonOrViolation(repoRoot, "manifest"),
    readJsonOrViolation(repoRoot, "signature"),
    readJsonOrViolation(repoRoot, "signers"),
    readJsonOrViolation(repoRoot, "signersSignature"),
    readJsonOrViolation(repoRoot, "registrationPublicKey")
  ]);

  return {
    manifest,
    signature,
    signers,
    signersSignature,
    registrationPublicKey,
    violations: [manifest, signature, signers, signersSignature, registrationPublicKey]
      .flatMap((item) => item.violation ? [item.violation] : [])
  };
}

async function readStagedMetadataOrViolations(repoRoot) {
  const [manifest, signature, signers, signersSignature, registrationPublicKey] = await Promise.all([
    readStagedJsonOrWorking(repoRoot, "manifest"),
    readStagedJsonOrWorking(repoRoot, "signature"),
    readStagedJsonOrWorking(repoRoot, "signers"),
    readStagedJsonOrWorking(repoRoot, "signersSignature"),
    readStagedJsonOrWorking(repoRoot, "registrationPublicKey")
  ]);

  return {
    manifest,
    signature,
    signers,
    signersSignature,
    registrationPublicKey,
    violations: [manifest, signature, signers, signersSignature, registrationPublicKey]
      .flatMap((item) => item.violation ? [item.violation] : [])
  };
}

async function readStagedJsonOrWorking(repoRoot, kind) {
  const text = await readStagedFile(repoRoot, pathForKind(kind));
  if (text === null) {
    return readJsonOrViolation(repoRoot, kind);
  }

  const value = parseJsonOrNull(text);
  if (!value) {
    return { violation: createViolation(invalidCodeForKind(kind)) };
  }
  return { value };
}

async function verifyMetadataValues(metadata) {
  const violations = [...metadata.violations];
  if (violations.length > 0) {
    return violations;
  }

  violations.push(...validateManifestShape(metadata.manifest.value).map((violation) => createViolation(violation.code, violation)));
  violations.push(...validateSignerRegistry(metadata.signers.value).map((violation) => createViolation(violation.code, violation)));
  if (violations.length > 0) {
    return violations;
  }

  const signersSignatureValid = await verifyPayloadSignature({
    payload: canonicalizeJson(metadata.signers.value),
    signature: metadata.signersSignature.value,
    publicKey: metadata.registrationPublicKey.value
  });
  if (!signersSignatureValid) {
    violations.push(createViolation("SIGNERS_SIGNATURE_INVALID"));
    return violations;
  }

  const signer = findActiveSigner(metadata.signers.value, metadata.signature.value.keyId ?? metadata.manifest.value.keyId);
  if (!signer || metadata.manifest.value.keyId !== signer.keyId) {
    violations.push(createViolation("MANIFEST_SIGNER_NOT_REGISTERED"));
    return violations;
  }

  const manifestSignatureValid = await verifyPayloadSignature({
    payload: canonicalizeJson(metadata.manifest.value),
    signature: metadata.signature.value,
    publicKey: publicKeyFromSigner(signer)
  });
  if (!manifestSignatureValid) {
    violations.push(createViolation("MANIFEST_SIGNATURE_INVALID"));
  }

  return violations;
}

function pathForKind(kind) {
  if (kind === "manifest") {
    return MANIFEST_PATH;
  }
  if (kind === "signature") {
    return SIGNATURE_PATH;
  }
  if (kind === "signers") {
    return SIGNERS_PATH;
  }
  if (kind === "signersSignature") {
    return SIGNERS_SIGNATURE_PATH;
  }
  return REGISTRATION_PUBLIC_KEY_PATH;
}
