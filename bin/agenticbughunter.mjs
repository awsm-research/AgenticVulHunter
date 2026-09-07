#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const bundledSource = path.join(packageRoot, "src");
const separator = process.platform === "win32" ? ";" : ":";
const env = {
  ...process.env,
  PYTHONPATH: [bundledSource, process.env.PYTHONPATH].filter(Boolean).join(separator),
};
const candidates = process.platform === "win32" ? ["py", "python"] : ["python3", "python"];
let result;
for (const executable of candidates) {
  result = spawnSync(executable, ["-m", "agenticbughunter.cli", ...process.argv.slice(2)], {
    env,
    stdio: "inherit",
  });
  if (!result.error || result.error.code !== "ENOENT") break;
}
if (result?.error) {
  console.error(`AgenticBugHunter requires Python 3.11 or newer: ${result.error.message}`);
  process.exit(127);
}
process.exit(result?.status ?? 1);
