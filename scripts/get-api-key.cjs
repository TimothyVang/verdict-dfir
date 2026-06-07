#!/usr/bin/env node
/*
 * get-api-key.cjs — browser-login API-key acquisition for Phase 2 grounding.
 *
 * Opens a HEADED browser at a provider's login page, waits for YOU to sign in,
 * then reads the API key off your account page and saves it to a gitignored file
 * under tmp/api-keys/. Nothing is ever committed; no password is touched by the
 * script — you authenticate yourself in the visible window.
 *
 *   node scripts/get-api-key.cjs virustotal      # -> tmp/api-keys/virustotal.txt
 *   node scripts/get-api-key.cjs abusech         # -> tmp/api-keys/abusech.txt
 *
 * Resolves Playwright from the global npm root (no local install needed) and
 * reuses a persistent browser profile so a second provider may already be authed.
 *
 * BOUNDARY: keys are operator secrets for the post-verdict grounding workflow
 * (agent-config/GROUNDING.md). They enrich analyst context; their results are
 * never evidence and never enter the audit/crypto chain.
 */
"use strict";

const { createRequire } = require("module");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// Resolve the globally-installed playwright regardless of NODE_PATH.
function loadPlaywright() {
  try {
    return require("playwright");
  } catch {
    const groot = execSync("npm root -g").toString().trim();
    const req = createRequire(path.join(groot, "/"));
    return req("playwright");
  }
}

const ROOT = path.resolve(__dirname, "..");
const KEY_DIR = path.join(ROOT, "tmp", "api-keys");
const PROFILE_DIR = path.join(KEY_DIR, ".chrome-profile");

// 64-char lowercase hex = a VirusTotal API key. Pick the first such token found
// anywhere in the rendered DOM (incl. shadow roots and input values).
const HEX64 = /\b[0-9a-f]{64}\b/;

const PROVIDERS = {
  virustotal: {
    name: "VirusTotal",
    // Open the key page directly; VT redirects to sign-in and returns here after.
    keyUrl: "https://www.virustotal.com/gui/my-apikey",
    signInHint: /sign-?in|\/auth|login/i,
    keyUrlHint: /my-apikey/i,
    pattern: HEX64,
    note: "Sign in (or create a free account). Your API key lives at Profile -> API key.",
  },
  abusech: {
    name: "abuse.ch",
    keyUrl: "https://auth.abuse.ch/",
    signInHint: /login|sign-?in/i,
    keyUrlHint: /auth\.abuse\.ch/i,
    // abuse.ch Auth-Keys are long opaque tokens; grab a long token from the page.
    pattern: /\b[A-Za-z0-9_-]{40,}\b/,
    note: "Log in at auth.abuse.ch; your Auth-Key is shown on the account page.",
  },
};

const EXTRACTOR = (patternSource) => {
  // Runs in the page: walk light + shadow DOM, collect text + input values.
  const re = new RegExp(patternSource);
  const texts = [];
  const visit = (root) => {
    if (!root || !root.querySelectorAll) return;
    root.querySelectorAll("input, textarea").forEach((i) => {
      if (i.value) texts.push(i.value);
    });
    if (root.textContent) texts.push(root.textContent);
    root.querySelectorAll("*").forEach((el) => {
      if (el.shadowRoot) visit(el.shadowRoot);
    });
  };
  visit(document);
  const m = texts.join(" \n ").match(re);
  return m ? m[0] : null;
};

async function main() {
  const which = (process.argv[2] || "virustotal").toLowerCase();
  const cfg = PROVIDERS[which];
  if (!cfg) {
    console.error(`unknown provider '${which}'. options: ${Object.keys(PROVIDERS).join(", ")}`);
    process.exit(2);
  }
  fs.mkdirSync(PROFILE_DIR, { recursive: true });
  const outFile = path.join(KEY_DIR, `${which}.txt`);

  const { chromium } = loadPlaywright();
  console.log(`[get-api-key] launching real Google Chrome for ${cfg.name}…`);
  // Drive the user's REAL Chrome (not Playwright's bundled Chromium) with the
  // automation fingerprints stripped, so Google SSO does not reject it as
  // "this browser or app may not be secure".
  const launchOpts = {
    headless: false,
    viewport: null,
    ignoreDefaultArgs: ["--enable-automation"],
    args: [
      "--disable-blink-features=AutomationControlled",
      "--no-first-run",
      "--no-default-browser-check",
    ],
  };
  let ctx;
  try {
    ctx = await chromium.launchPersistentContext(PROFILE_DIR, {
      ...launchOpts,
      channel: "chrome",
    });
  } catch {
    ctx = await chromium.launchPersistentContext(PROFILE_DIR, {
      ...launchOpts,
      executablePath: "/usr/bin/google-chrome",
    });
  }
  // Hide navigator.webdriver before any page script runs (Google checks it).
  await ctx.addInitScript(() => {
    Object.defineProperty(navigator, "webdriver", { get: () => undefined });
  });
  const page = ctx.pages()[0] || (await ctx.newPage());

  try {
    await page.goto(cfg.keyUrl, { waitUntil: "domcontentloaded", timeout: 45000 });
  } catch {
    /* slow first paint is fine; the poll loop will retry */
  }

  console.log("");
  console.log(`  >>> Please LOG IN to ${cfg.name} in the window that just opened.`);
  console.log(`      ${cfg.note}`);
  console.log("      I'll detect the key automatically once you're in (up to 8 min).");
  console.log("");

  const deadline = Date.now() + 8 * 60 * 1000;
  let key = null;
  while (Date.now() < deadline) {
    await page.waitForTimeout(4000);
    let url = "";
    try {
      url = page.url();
    } catch {
      continue; // page navigating
    }
    // While the user is on a sign-in page, don't disturb them.
    if (cfg.signInHint.test(url) && !cfg.keyUrlHint.test(url)) continue;
    // Logged in but not on the key page -> bring them there once.
    if (!cfg.keyUrlHint.test(url)) {
      try {
        await page.goto(cfg.keyUrl, { waitUntil: "domcontentloaded", timeout: 30000 });
        await page.waitForTimeout(1500);
      } catch {
        continue;
      }
    }
    try {
      key = await page.evaluate(EXTRACTOR, cfg.pattern.source);
    } catch {
      key = null;
    }
    if (key) break;
  }

  if (!key) {
    console.error(`[get-api-key] timed out without finding a ${cfg.name} key. Leaving the window open is fine; re-run when ready.`);
    await ctx.close();
    process.exit(1);
  }

  fs.writeFileSync(outFile, key + "\n", { mode: 0o600 });
  console.log(`[get-api-key] saved ${cfg.name} key -> ${path.relative(ROOT, outFile)} (gitignored)`);
  console.log(`[get-api-key] key length=${key.length}, preview=${key.slice(0, 4)}…${key.slice(-4)}`);
  await ctx.close();
  process.exit(0);
}

main().catch((e) => {
  console.error("[get-api-key] error:", e && e.message ? e.message : e);
  process.exit(1);
});
