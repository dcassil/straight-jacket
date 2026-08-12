import { normalizeRepoPath } from "../git/paths.js";
import { createProtectedEntry, sortEntries } from "../manifest/entries.js";
import { validateEntrySet } from "../manifest/validation.js";
import { assertAuthorizedSigner } from "../signing/authorization.js";
import { createCodedError } from "./errors.js";
import { loadVerifiedManifest, signAndWriteManifest } from "./manifest-state.js";

export async function addProtectedFile({ repoRoot, path, password, reason, now } = {}) {
  const protectedPath = normalizeRepoPath(path);
  const { manifest } = await loadVerifiedManifest(repoRoot);
  const entrySetViolations = validateEntrySet([...manifest.entries, { path: protectedPath }]);
  if (entrySetViolations.length > 0) {
    throw createCodedError(entrySetViolations[0].code, "Protected path is already registered", {
      violations: entrySetViolations
    });
  }

  const signer = await assertAuthorizedSigner({ repoRoot, password });
  const entry = await createProtectedEntry({
    repoRoot,
    path: protectedPath,
    reason,
    now
  });
  const nextManifest = {
    ...manifest,
    entries: sortEntries([...manifest.entries, entry])
  };

  await signAndWriteManifest({
    repoRoot,
    manifest: nextManifest,
    privateKey: signer.privateKey,
    keyId: signer.keyId,
    now
  });

  return {
    ok: true,
    entry
  };
}
