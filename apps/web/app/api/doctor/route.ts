// Preflight endpoint — runs `scripts/doctor.sh --json` and returns its
// machine-readable report so the /setup page can guide an operator through
// installing missing DFIR tools in the browser. Read-only: doctor.sh inspects
// PATH and prints; it takes no user input and mutates nothing.
//
// Usage: GET /api/doctor  ->  { ready, missing_required, checks[], remedies[] }

import { spawn } from "node:child_process";
import path from "node:path";

import { requireRepoRoot } from "@/lib/repo-root";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  let root: string;
  try {
    root = requireRepoRoot();
  } catch (e) {
    return new Response(
      JSON.stringify({
        error: e instanceof Error ? e.message : String(e),
        hint: "Launch from the repo root or set FINDEVIL_REPO_ROOT to the repo root.",
      }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
  const scriptPath = path.join("scripts", "doctor.sh");

  const result = await new Promise<{ code: number; out: string; err: string }>((resolve) => {
    const child = spawn("bash", [scriptPath, "--json"], { cwd: root });
    let out = "";
    let err = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
    child.stdout.on("data", (d) => (out += d.toString()));
    child.stderr.on("data", (d) => (err += d.toString()));
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, out, err });
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ code: -1, out, err: e instanceof Error ? e.message : String(e) });
    });
  });

  try {
    return Response.json(JSON.parse(result.out));
  } catch {
    return new Response(
      JSON.stringify({
        error: "doctor.sh did not return valid JSON",
        exit: result.code,
        stderr: result.err.slice(0, 500),
        hint: "Ensure the dashboard was launched with FINDEVIL_REPO_ROOT set to the repo root.",
      }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }
}
