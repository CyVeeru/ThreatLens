#!/usr/bin/env node
const { spawnSync } = require("node:child_process");

const baseline = Number(process.env.THREATLENS_PRETTIER_BASELINE || "0");
const verbose = process.env.THREATLENS_PRETTIER_VERBOSE === "1" || process.argv.includes("--verbose");

// Invoke the local prettier through the current Node binary (see
// typecheck-baseline.cjs for why `npx.cmd` is not used). Checking `.` with
// Prettier's default ignore handling (.gitignore + .prettierignore) covers the
// tracked tree without exceeding the Windows argv length limit.
const result = spawnSync(
  process.execPath,
  [require.resolve("prettier/bin/prettier.cjs"), "--check", "--no-color", "."],
  { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
);
if (result.error) {
  process.stderr.write(`Unable to run prettier: ${result.error.message}\n`);
  process.exit(1);
}
// Prettier colourises even when piped; strip escape codes so the [warn] lines
// are countable regardless of TTY detection.
// eslint-disable-next-line no-control-regex
const output = `${result.stdout || ""}${result.stderr || ""}`.replace(/\x1b\[[0-9;]*m/g, "");
const filesNeedingFormat = (output.match(/^\[warn\] .+$/gm) || []).filter(
  (line) => !line.includes("Code style issues found"),
).length;

if (filesNeedingFormat === 0) {
  process.stdout.write("Prettier check passed with 0 files needing formatting.\n");
  process.exit(0);
}

process.stdout.write(`Prettier files needing formatting: ${filesNeedingFormat}`);
if (baseline > 0) process.stdout.write(` (baseline: ${baseline})`);
process.stdout.write("\n");

if (verbose) process.stdout.write(output);

if (baseline <= 0 || filesNeedingFormat > baseline) {
  process.stderr.write(
    baseline > 0
      ? `Prettier deviation count increased above baseline ${baseline}. Run npm run format on the affected files.\n`
      : "Set THREATLENS_PRETTIER_BASELINE to freeze the current formatting debt while it is reduced.\n",
  );
  process.exit(1);
}

process.stdout.write("Prettier baseline gate passed; formatting debt did not grow.\n");
