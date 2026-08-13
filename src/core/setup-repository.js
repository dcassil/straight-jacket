import { access } from "node:fs/promises";
import { assertGitRepoRoot } from "../git/repo.js";
import { manifestPath } from "../manifest/read-write.js";
import { createSigningKey, exportPublicKey } from "../signing/keys.js";
import { encryptPrivateKey, writeEncryptedPrivateKey } from "../signing/private-key-store.js";
import {
  createSignerRecord,
  findActiveSigner,
  loadVerifiedSignerRegistry,
  signAndWriteSignerRegistry,
  sortSigners,
  unlockRegistrationSigner
} from "../signing/signer-registry.js";
import { checkLocalSigner } from "../signing/authorization.js";
import { initRepository } from "./init-repository.js";
import { verifyRepository } from "./verify-repository.js";

export async function setupRepository({ repoRoot, password, masterPassword, localPassword, now } = {}) {
  await assertGitRepoRoot(repoRoot);
  const registrationPassword = masterPassword ?? password;
  const signerPassword = localPassword ?? password;

  if (!await isRepositoryInitialized(repoRoot)) {
    return initRepository({
      repoRoot,
      masterPassword: registrationPassword,
      localPassword: signerPassword,
      now
    });
  }

  const verification = await verifyRepository({ repoRoot, scope: "working-tree" });
  if (!verification.ok) {
    return {
      ...verification,
      setupRequired: true
    };
  }

  try {
    const local = await checkLocalSigner({ repoRoot });
    return {
      ok: true,
      alreadyRegistered: true,
      signerKeyId: local.signerKeyId
    };
  } catch (error) {
    if (error.code !== "LOCAL_SIGNER_MISSING" && error.code !== "LOCAL_SIGNER_NOT_REGISTERED") {
      throw error;
    }
  }

  const registrationSigner = await unlockRegistrationSigner({
    repoRoot,
    masterPassword: registrationPassword
  });
  const { registry } = await loadVerifiedSignerRegistry(repoRoot);
  const localKeyPair = await createSigningKey();
  const localPublicKey = await exportPublicKey(localKeyPair);
  const existingSigner = findActiveSigner(registry, localPublicKey.keyId);
  if (existingSigner) {
    return {
      ok: true,
      alreadyRegistered: true,
      signerKeyId: existingSigner.keyId
    };
  }

  const encryptedPrivateKey = await encryptPrivateKey({
    privateKey: localKeyPair.privateKey,
    password: signerPassword,
    publicKeyFingerprint: localPublicKey.fingerprint
  });
  const nextRegistry = {
    ...registry,
    signers: sortSigners([
      ...registry.signers,
      createSignerRecord({
        publicKey: localPublicKey,
        registeredAt: now
      })
    ])
  };

  await signAndWriteSignerRegistry({
    repoRoot,
    registry: nextRegistry,
    privateKey: registrationSigner.privateKey,
    keyId: registrationSigner.keyId,
    now
  });
  await writeEncryptedPrivateKey(repoRoot, encryptedPrivateKey);

  return {
    ok: true,
    registered: true,
    signerKeyId: localPublicKey.keyId
  };
}

export async function checkRepositorySetup({ repoRoot } = {}) {
  await assertGitRepoRoot(repoRoot);
  const local = await checkLocalSigner({ repoRoot });
  return {
    ok: true,
    signerKeyId: local.signerKeyId
  };
}

export async function isRepositoryInitialized(repoRoot) {
  try {
    await access(manifestPath(repoRoot));
    return true;
  } catch (error) {
    if (error.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}
