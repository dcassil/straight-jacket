const VIOLATION_MESSAGES = {
  CHECKSUM_MISMATCH: ({ path }) => `${path} checksum changed`,
  PROTECTED_FILE_MISSING: ({ path }) => `${path} is missing`,
  LIKELY_RENAME_OR_MOVE: ({ path }) => `${path} appears to contain a protected file moved from another path`,
  MANIFEST_MISSING: () => "Straight Jacket manifest is missing",
  MANIFEST_SIGNATURE_MISSING: () => "Straight Jacket manifest signature is missing",
  PUBLIC_KEY_MISSING: () => "Straight Jacket public key is missing"
};

export function createViolation(code, fields = {}) {
  const messageFactory = VIOLATION_MESSAGES[code];
  return {
    code,
    ...fields,
    message: messageFactory ? messageFactory(fields) : code
  };
}
