import type { NextConfig } from "next";

const isL1Docker = process.env.FINDEVIL_L1_DOCKER === "1";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  ...(isL1Docker
    ? {
        eslint: { ignoreDuringBuilds: true },
        experimental: { cpus: 1, workerThreads: false },
        typescript: { ignoreBuildErrors: true },
      }
    : {}),
  // The dashboard reads audit JSONL from absolute filesystem paths
  // passed via `?case=` query string. No outbound network required at
  // runtime; everything is local to the host running Claude Code +
  // the case directory.
};

export default nextConfig;
