#!/usr/bin/env node

import { promises as fs } from "fs";
import path from "path";
import process from "process";

const root = process.argv[2] ? path.resolve(process.argv[2]) : process.cwd();
const maxFiles = Number.parseInt(process.argv[3] || "1000", 10);
const maxBytes = Number.parseInt(process.argv[4] || "1048576", 10);

const EXCLUDED_DIRS = new Set([
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "target",
  ".venv",
  ".idea",
  ".vscode",
  "__pycache__",
  ".pytest_cache",
  ".mypy_cache",
  ".ruff_cache",
  ".tox",
  ".cache",
  ".sentinelayer",
]);

const stats = {
  total_files: 0,
  binary_files: 0,
  too_large: 0,
  truncated: false,
  read_failures: 0,
};

const files = [];

function normalizePath(p) {
  return p.split(path.sep).join("/");
}

async function isBinaryFile(filePath) {
  const handle = await fs.open(filePath, "r");
  try {
    const buffer = Buffer.alloc(4096);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead === 0) {
      return false;
    }
    let nonText = 0;
    for (let i = 0; i < bytesRead; i += 1) {
      const byte = buffer[i];
      if (byte === 0) {
        return true;
      }
      if (byte < 7 || (byte > 14 && byte < 32) || byte === 127) {
        nonText += 1;
      }
    }
    return nonText / bytesRead > 0.3;
  } finally {
    await handle.close();
  }
}

async function walk(dir) {
  if (files.length >= maxFiles) {
    stats.truncated = true;
    return;
  }

  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    stats.read_failures += 1;
    return;
  }

  for (const entry of entries) {
    if (files.length >= maxFiles) {
      stats.truncated = true;
      return;
    }

    const fullPath = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      if (EXCLUDED_DIRS.has(entry.name) || entry.name.startsWith(".tmp-run-")) {
        continue;
      }
      await walk(fullPath);
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }

    let fileStat;
    try {
      fileStat = await fs.stat(fullPath);
    } catch {
      stats.read_failures += 1;
      continue;
    }

    stats.total_files += 1;
    const sizeBytes = fileStat.size;
    if (sizeBytes > maxBytes) {
      stats.too_large += 1;
      continue;
    }

    const binary = await isBinaryFile(fullPath);
    if (binary) {
      stats.binary_files += 1;
      continue;
    }

    const relPath = normalizePath(path.relative(root, fullPath));
    files.push({
      path: relPath,
      size_bytes: sizeBytes,
      is_binary: false,
    });
  }
}

async function main() {
  await walk(root);
  const output = {
    root,
    files,
    stats,
  };
  process.stdout.write(JSON.stringify(output));
}

main().catch((err) => {
  process.stderr.write(String(err));
  process.exit(1);
});
