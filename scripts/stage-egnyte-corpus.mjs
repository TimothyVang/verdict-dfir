#!/usr/bin/env node
// stage-egnyte-corpus.mjs — download a public Egnyte folder share, file by file.
//
// Why per-file: Egnyte's "Download Folder" zip endpoint returns HTTP 400 on
// large public shares (zip-folder needs login), so the only reliable path is to
// drive each file's preview + Download button through a browser. Each file gets
// a FRESH browser (no cross-file SPA navigation, so one failure can't cascade),
// with retries, magic-byte verification, and skip-if-present (resumable).
//
// Usage:
//   node scripts/stage-egnyte-corpus.mjs <manifest.json> <dest-dir> [--only <substr>] [--dry-run]
//
// Manifest shape (see scripts/egnyte-corpus.srl-2018.json):
//   { "share": "https://<org>.egnyte.com/fl/<token>",
//     "rootPath": "#folder-link/...url-encoded-path...",
//     "groups": [ { "subPath": "", "dest": "disks", "files": ["a.E01", ...] },
//                 { "subPath": "/Sub", "dest": "mem", "files": ["b.7z", ...] } ] }
//
// Env:
//   PLAYWRIGHT_DIR   dir containing the `playwright` module (if not resolvable normally)
//   HEADLESS=0       run headed (default headless)
import { createRequire } from 'module';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const require = createRequire(import.meta.url);

async function loadChromium() {
  const candidates = [];
  if (process.env.PLAYWRIGHT_DIR) candidates.push(path.join(process.env.PLAYWRIGHT_DIR, 'index.js'));
  candidates.push('playwright');
  try { candidates.push(path.join(execSync('npm root -g', { encoding: 'utf8' }).trim(), 'playwright', 'index.js')); } catch { /* npm absent */ }
  for (const c of candidates) {
    try { const m = await import(c); return (m.default || m).chromium; } catch { /* try next */ }
  }
  throw new Error('playwright not found. Install it (`npm i -g playwright && npx playwright install chromium`) or set PLAYWRIGHT_DIR.');
}

const MAGIC = {
  e01: ['45', '56', '46', '09'],            // EVF\x09  (EnCase E01)
  '7z': ['37', '7a', 'bc', 'af', '27', '1c'], // 7z..'.
  zip: ['50', '4b', '03', '04'],            // PK\x03\x04
  img: null, raw: null, dd: null,           // raw images: no reliable magic
};
const ext = (name) => { const e = name.split('.').pop().toLowerCase(); return e === 'e01' ? 'e01' : e; };
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

async function magicOk(file, name) {
  const want = MAGIC[ext(name)];
  if (!want) return true;
  const fd = await fs.promises.open(file, 'r');
  const buf = Buffer.alloc(want.length);
  await fd.read(buf, 0, want.length, 0);
  await fd.close();
  const got = [...buf].map((b) => b.toString(16).padStart(2, '0'));
  return want.every((w, i) => w === got[i]);
}

async function downloadOne(chromium, url, name, dest, headless) {
  const browser = await chromium.launch({ headless });
  try {
    const ctx = await browser.newContext({ acceptDownloads: true });
    const page = await ctx.newPage();
    page.setDefaultTimeout(120000);
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    const fileBtn = page.getByRole('button', { name, exact: true }).first();
    await fileBtn.waitFor({ state: 'visible', timeout: 120000 });
    await fileBtn.click();
    const dlBtn = page.getByRole('dialog').getByRole('button', { name: 'Download' }).first();
    await dlBtn.waitFor({ state: 'visible', timeout: 60000 });
    const dlPromise = page.waitForEvent('download', { timeout: 0 });
    await dlBtn.click();
    const download = await dlPromise;
    await download.saveAs(dest); // resolves only when fully written
  } finally {
    await browser.close().catch(() => {});
  }
}

async function main() {
  const [manifestPath, destDir, ...rest] = process.argv.slice(2);
  if (!manifestPath || !destDir) {
    console.error('usage: stage-egnyte-corpus.mjs <manifest.json> <dest-dir> [--only <substr>] [--dry-run]');
    process.exit(2);
  }
  const only = rest.includes('--only') ? rest[rest.indexOf('--only') + 1] : null;
  const dryRun = rest.includes('--dry-run');
  const headless = process.env.HEADLESS !== '0';
  const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

  const targets = [];
  for (const g of m.groups) {
    const url = `${m.share}${m.rootPath}${g.subPath || ''}`;
    for (const name of g.files) {
      if (only && !name.includes(only)) continue;
      targets.push({ name, url, dir: g.dest });
    }
  }

  log(`staging ${targets.length} file(s) -> ${destDir}  headless=${headless}${dryRun ? '  [dry-run]' : ''}`);
  if (dryRun) { targets.forEach((t) => console.log(`  ${t.dir}/${t.name}  <-  ${t.url}`)); return; }

  const chromium = await loadChromium();
  const results = [];
  for (const t of targets) {
    const dDir = path.join(destDir, t.dir);
    fs.mkdirSync(dDir, { recursive: true });
    const dest = path.join(dDir, t.name);
    if (fs.existsSync(dest) && fs.statSync(dest).size > 1_000_000) {
      log('SKIP (present)', t.name); results.push({ name: t.name, status: 'skip' }); continue;
    }
    let done = false;
    for (let attempt = 1; attempt <= 2 && !done; attempt++) {
      try {
        log('GET', t.name, attempt > 1 ? `(retry ${attempt})` : '', '...');
        await downloadOne(chromium, t.url, t.name, dest, headless);
        if (!(await magicOk(dest, t.name))) { fs.unlinkSync(dest); throw new Error('bad magic bytes'); }
        const size = fs.statSync(dest).size;
        log('DONE', t.name, (size / 1e9).toFixed(2) + 'GB', 'magic OK');
        results.push({ name: t.name, status: 'ok', size }); done = true;
      } catch (e) {
        log('ERROR', t.name, '-', e.message.split('\n')[0]);
        try { if (fs.existsSync(dest) && fs.statSync(dest).size < 1_000_000) fs.unlinkSync(dest); } catch { /* ignore */ }
        if (attempt === 2) results.push({ name: t.name, status: 'error', error: e.message.split('\n')[0] });
      }
    }
  }

  fs.writeFileSync(path.join(destDir, '_stage-results.json'), JSON.stringify(results, null, 2));
  const ok = results.filter((r) => r.status === 'ok').length;
  const sk = results.filter((r) => r.status === 'skip').length;
  const bad = results.filter((r) => r.status === 'error');
  log(`SUMMARY ok=${ok} skip=${sk} failed=${bad.length}`);
  if (bad.length) { log('FAILED:', bad.map((b) => b.name).join(', ')); process.exit(1); }
}

main().catch((e) => { console.error(e); process.exit(1); });
