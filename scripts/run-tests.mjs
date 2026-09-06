import {spawnSync} from "node:child_process";
import {readdirSync, statSync} from "node:fs";
import {join} from "node:path";

const root = process.argv[2] ?? "dist/tests";

const collect = (dir) => {
  const files = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) files.push(...collect(full));
    else if (entry.endsWith(".test.js")) files.push(full);
  }
  return files;
};

const files = collect(root).sort();
if (files.length === 0) {
  console.error(`no *.test.js files found under ${root}`);
  process.exit(1);
}

const result = spawnSync(process.execPath, ["--test", ...files], {stdio: "inherit"});
process.exit(result.status ?? 1);
