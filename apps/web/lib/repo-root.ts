import fs from "node:fs";
import path from "node:path";

const REPO_MARKERS = [
  path.join("scripts", "doctor.sh"),
  path.join("apps", "web", "package.json"),
  "pnpm-workspace.yaml",
];

function hasRepoMarkers(dir: string): boolean {
  return REPO_MARKERS.every((marker) => fs.existsSync(path.join(dir, marker)));
}

function findRepoRoot(startDir: string): string | null {
  let dir = path.resolve(startDir);
  while (true) {
    if (hasRepoMarkers(dir)) return dir;

    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

export function repoRoot(startDir = process.cwd()): string {
  const root = process.env.FINDEVIL_REPO_ROOT
    ? path.resolve(process.env.FINDEVIL_REPO_ROOT)
    : findRepoRoot(startDir);

  if (!root || !hasRepoMarkers(root)) {
    throw new Error("Unable to find VERDICT repo root");
  }

  return root;
}

export const requireRepoRoot = repoRoot;
