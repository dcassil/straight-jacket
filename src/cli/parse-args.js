import { createCodedError } from "../core/errors.js";

const BOOLEAN_FLAGS = new Set(["json", "staged"]);
const VALUE_FLAGS = new Set(["reason", "provider", "trusted-public-key-fingerprint"]);
const FORBIDDEN_PASSWORD_FLAGS = new Set(["password", "password-file"]);

export function parseArgs(argv) {
  const [command, ...tokens] = argv;
  if (!command) {
    throw createCodedError("USAGE_ERROR", "Command is required");
  }

  const positional = [];
  const flags = {};

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith("--")) {
      positional.push(token);
      continue;
    }

    const flagName = token.slice(2);
    if (FORBIDDEN_PASSWORD_FLAGS.has(flagName)) {
      throw createCodedError("PASSWORD_SOURCE_NOT_ALLOWED", "Passwords must be entered interactively");
    }

    if (BOOLEAN_FLAGS.has(flagName)) {
      flags[toCamelFlag(flagName)] = true;
      continue;
    }

    if (VALUE_FLAGS.has(flagName)) {
      const value = tokens[index + 1];
      if (value === undefined || value.startsWith("--")) {
        throw createCodedError("USAGE_ERROR", `Missing value for --${flagName}`);
      }
      flags[toCamelFlag(flagName)] = value;
      index += 1;
      continue;
    }

    throw createCodedError("USAGE_ERROR", `Unknown flag --${flagName}`);
  }

  return {
    command,
    positional,
    flags
  };
}

function toCamelFlag(flagName) {
  return flagName.replace(/-([a-z])/g, (_, character) => character.toUpperCase());
}
