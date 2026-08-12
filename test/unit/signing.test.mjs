import assert from "node:assert/strict";
import test from "node:test";

test("signing creates Ed25519 key material and public fingerprint without exposing private key in public payload", async () => {
  const { createSigningKey, exportPublicKey, fingerprintPublicKey } = await import("../../src/signing/keys.js");

  const keyPair = await createSigningKey();
  const publicKey = await exportPublicKey(keyPair);
  const fingerprint = fingerprintPublicKey(publicKey);

  assert.equal(publicKey.algorithm, "ed25519");
  assert.match(fingerprint, /^sha256:[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(publicKey).includes("private"), false);
});

test("signing verifies canonical payloads and rejects tampered payloads", async () => {
  const { createSigningKey, exportPublicKey } = await import("../../src/signing/keys.js");
  const { signPayload, verifyPayloadSignature } = await import("../../src/signing/signatures.js");

  const keyPair = await createSigningKey();
  const publicKey = await exportPublicKey(keyPair);
  const payload = '{"entries":[],"version":1}';
  const signature = await signPayload({ payload, privateKey: keyPair.privateKey, keyId: publicKey.keyId, now: "2026-08-12T00:00:00.000Z" });

  assert.equal(signature.algorithm, "ed25519");
  assert.equal(await verifyPayloadSignature({ payload, signature, publicKey }), true);
  assert.equal(await verifyPayloadSignature({ payload: '{"entries":[1],"version":1}', signature, publicKey }), false);
});

test("encrypted private key unlock succeeds only with the original password", async () => {
  const { createSigningKey } = await import("../../src/signing/keys.js");
  const { encryptPrivateKey, decryptPrivateKey } = await import("../../src/signing/private-key-store.js");

  const keyPair = await createSigningKey();
  const encrypted = await encryptPrivateKey({
    privateKey: keyPair.privateKey,
    password: "correct horse battery staple",
    publicKeyFingerprint: "sha256:" + "a".repeat(64)
  });

  assert.equal(JSON.stringify(encrypted).includes("correct horse battery staple"), false);
  await assert.doesNotReject(() => decryptPrivateKey({ encrypted, password: "correct horse battery staple" }));
  await assert.rejects(() => decryptPrivateKey({ encrypted, password: "wrong" }), /INVALID_PASSWORD/);
});
