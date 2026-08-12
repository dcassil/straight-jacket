import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const root = process.cwd();
const srcRoot = path.join(root, "src");
const failures = [];

const forbiddenPasswordPatterns = [
  {
    pattern: /process\.env\.(STRAIGHT_JACKET_PASSWORD|SJ_PASSWORD)/,
    message: "Passwords must not be accepted from default environment variables."
  },
  {
    pattern: /\bpasswordFile\b|\bpassword_file\b/,
    message: "Mutating commands must not accept repo-file password sources."
  },
  {
    pattern: /readFile(?:Sync)?\([^)]*password/i,
    message: "Passwords must not be read from files."
  }
];

for (const file of listFiles(srcRoot)) {
  const text = readFileSync(file, "utf8");

  for (const { pattern, message } of forbiddenPasswordPatterns) {
    if (pattern.test(text)) {
      failures.push(`${relative(file)}: ${message}`);
    }
  }

  if (file.endsWith(path.join("src", "mcp.js"))) {
    const forbiddenMcpToolNames = [
      "straight_jacket_add",
      "straight_jacket_remove",
      "straight_jacket_update",
      "straight_jacket_rename",
      "straight_jacket_capture_password",
      "straight_jacket_export_private_key"
    ];

    for (const toolName of forbiddenMcpToolNames) {
      if (text.includes(toolName)) {
        failures.push(`${relative(file)}: MCP must not expose silent mutation or secret-export tool ${toolName}.`);
      }
    }
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}

console.log("boundary guardrails ok");

function listFiles(directory) {
  if (!existsSync(directory)) {
    return [];
  }

  const files = [];
  for (const entry of readdirSync(directory)) {
    const fullPath = path.join(directory, entry);
    const stats = statSync(fullPath);
    if (stats.isDirectory()) {
      files.push(...listFiles(fullPath));
  } else if (/\.(js|mjs|ts|mts)$/.test(entry)) {
      files.push(fullPath);
    }
  }
  return files;
}

function relative(file) {
  return path.relative(root, file);
}
