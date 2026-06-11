#!/usr/bin/env node
// scripts/fetch-sift-ova.cjs — headless Playwright fetcher for the SANS SIFT
// Workstation OVA (the one gated asset a plain shell can't curl).
//
// Reads the `sift-ova` entry in scripts/gated-tools.json, then:
//   1. navigates the SANS landing page and reads the public Egnyte share href
//      (matches sansorg.egnyte.com/dl/ — the token rotates, never hardcoded),
//   2. opens that public share (no login), and
//   3. clicks Download, capturing the file into the download dir.
//
// It is BEST-EFFORT and HONEST about failure: any step that breaks (site
// changed, blocked, partial/HTML response, offline) exits non-zero with a clear
// reason so `scripts/setup --with-sift` can fall back to the Claude/manual path.
// Local-host mode never needs this asset.
//
// Usage:
//   node scripts/fetch-sift-ova.cjs            # full fetch (~8.8 GB)
//   node scripts/fetch-sift-ova.cjs --probe    # navigate + locate only, no download
// Env:
//   FINDEVIL_DOWNLOAD_DIR   where to save (default: <repo>/tmp/gated-downloads)
// On success prints the saved file path to stdout and exits 0.

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const PROBE = process.argv.includes("--probe");
const REPO = path.resolve(__dirname, "..");

function log(msg) {
  process.stderr.write(`[sift-fetch] ${msg}\n`);
}

// Return the path of an existing valid OVA (>= minBytes, not an HTML page) in any
// of `dirs`, or null. Lets the fetcher reuse a prior download instead of pulling
// ~8.8 GB again.
function findExistingOva(dirs, minBytes) {
  for (const dir of dirs) {
    let names = [];
    try {
      names = fs.readdirSync(dir).filter((f) => f.toLowerCase().endsWith(".ova"));
    } catch (_) {
      continue;
    }
    for (const name of names) {
      const p = path.join(dir, name);
      try {
        if (fs.statSync(p).size >= minBytes) {
          const head = fs.readFileSync(p, { encoding: "latin1", flag: "r" }).slice(0, 512);
          if (!/<!doctype|<html/i.test(head)) return p;
        }
      } catch (_) {
        /* unreadable — skip */
      }
    }
  }
  return null;
}

function loadPlaywright() {
  // Prefer an explicit dir, then the global npm root (install.sh installs
  // playwright globally), then plain resolution.
  const candidates = [];
  if (process.env.PLAYWRIGHT_DIR) candidates.push(process.env.PLAYWRIGHT_DIR);
  try {
    candidates.push(execSync("npm root -g", { encoding: "utf8" }).trim());
  } catch (_) {
    /* npm absent — fall through */
  }
  for (const base of candidates) {
    if (!base) continue;
    try {
      return require(path.join(base, "playwright"));
    } catch (_) {
      /* try next */
    }
  }
  return require("playwright"); // last resort: local resolution
}

async function main() {
  const regPath = path.join(REPO, "scripts/gated-tools.json");
  let tool;
  try {
    const reg = JSON.parse(fs.readFileSync(regPath, "utf8"));
    tool = (reg.tools || []).find((t) => t.id === "sift-ova");
  } catch (e) {
    log(`could not read ${regPath}: ${e.message}`);
    process.exit(2);
  }
  if (!tool || !tool.landing_url) {
    log("sift-ova entry (or landing_url) missing from gated-tools.json");
    process.exit(2);
  }
  const landing = tool.landing_url;
  const minBytes = (tool.verify && tool.verify.min_bytes) || 8e9;
  const dlDir =
    process.env.FINDEVIL_DOWNLOAD_DIR || path.join(REPO, "tmp/gated-downloads");
  fs.mkdirSync(dlDir, { recursive: true });

  // Reuse a valid OVA we already have (repo root or the download dir) instead of
  // pulling ~8.8 GB again.
  const existing = findExistingOva([REPO, dlDir], minBytes);
  if (existing) {
    log(`OVA already present — reusing ${existing} (no download)`);
    console.log(existing);
    process.exit(0);
  }

  let chromium;
  try {
    ({ chromium } = loadPlaywright());
  } catch (e) {
    log(`playwright not installed (${e.message.split("\n")[0]}). Run scripts/install.sh first.`);
    process.exit(3);
  }

  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  try {
    log(`navigating ${landing}`);
    await page.goto(landing, { waitUntil: "domcontentloaded", timeout: 60000 });

    // The SANS page links out to a public Egnyte share (sansorg.egnyte.com/dl/).
    const shareUrl = await page.evaluate(() => {
      const a = [...document.querySelectorAll("a")].find((el) =>
        /sansorg\.egnyte\.com\/dl\//i.test(el.href),
      );
      return a ? a.href : null;
    });
    if (!shareUrl) {
      throw new Error(
        "could not find the Egnyte share link (sansorg.egnyte.com/dl/) on the SANS page — the site layout may have changed",
      );
    }
    log(`egnyte share: ${shareUrl}`);

    await page.goto(shareUrl, { waitUntil: "domcontentloaded", timeout: 60000 });
    const downloadBtn = page.getByRole("button", { name: /download/i }).first();
    await downloadBtn.waitFor({ state: "visible", timeout: 30000 }).catch(() => {
      throw new Error(
        "the Egnyte share opened but no 'Download' button was found — the share UI may have changed",
      );
    });

    if (PROBE) {
      log("probe OK — share + Download button located (no download performed)");
      await browser.close();
      console.log(shareUrl);
      process.exit(0);
    }

    log("clicking Download — the OVA is ~8.8 GB, this will take a while...");
    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 180000 }),
      downloadBtn.click(),
    ]);
    const suggested = download.suggestedFilename() || "sift.ova";
    const dest = path.join(dlDir, suggested);
    await download.saveAs(dest);

    const size = fs.statSync(dest).size;
    if (size < minBytes) {
      throw new Error(
        `downloaded file is ${size} bytes (< ${minBytes}) — likely an HTML error page or a partial download, not the OVA`,
      );
    }
    log(`saved ${suggested} (${(size / 1e9).toFixed(1)} GB)`);
    await browser.close();
    console.log(dest); // stdout = the saved path, for the caller
    process.exit(0);
  } catch (e) {
    log(e.message);
    try {
      await browser.close();
    } catch (_) {
      /* ignore */
    }
    process.exit(1);
  }
}

main().catch((e) => {
  log(`unexpected: ${e && e.message ? e.message : e}`);
  process.exit(1);
});
