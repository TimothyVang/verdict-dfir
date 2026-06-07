---
source_url: https://www.mandiant.com/resources/blog/caching-out-the-val-of-shimcache-for-investigations
retrieved: 2026-06-06
fetched_with: NOT auto-scraped (live page is Cloudflare/JS-protected; plain HTTP returns nav chrome only, and browser fetchers need system libs not installed on this host)
trust: UNTRUSTED third-party summary captured for DFIR claim substantiation; verify against the live source before relying. Copyright remains with the original publisher (Mandiant/Google).
---

> Source: https://www.mandiant.com/resources/blog/caching-out-the-val-of-shimcache-for-investigations
> **Auto-scrape status: STUB.** The live Mandiant article body could not be
> retrieved automatically from this host — the page sits behind Cloudflare/JS
> and Scrapling's HTTP fetcher returns only the page shell. Scrapling's
> browser fetchers (`fetch` / `stealthy-fetch`) need Playwright system
> libraries that could not be installed non-interactively here
> (`sudo playwright install-deps` would fix it). Read the live page, or see
> the corroborating capture in [`withsecure-chainsaw-shimcache.md`](./withsecure-chainsaw-shimcache.md).

---

## Why this source matters

Mandiant's "Caching Out: The Value of Shimcache for Investigations" is the
primary source behind the ShimCache correction made in PR #17. The
deep-research adversarial pass (3 independent votes) **REFUTED** the prior
repo claim that ShimCache uses top-down LRU ordering.

## Verified findings attributed to this source (per the research pass)

- ShimCache (AppCompatCache) is **insertion / append-ordered, NOT LRU** —
  entry position is **not** recency of use. (This refuted the repo's prior
  "LRU-ish" phrasing.)
- ShimCache **presence does not prove execution**: entries are created by
  broad file interaction (install, file creation, first execution) and, on
  Vista/7/Server 2008/2012, by the Application Experience Lookup Service
  recording files in interactively browsed directories.
- The recorded ShimCache timestamp is the file's **`$STANDARD_INFORMATION`
  last-modified time**, not an insertion or execution timestamp.
- On Windows 10 / Server 2016+, the insert/execution flag was removed,
  further weakening any "presence = execution" reading.

## Corroborating source (auto-scraped successfully)

- WithSecure Chainsaw ShimCache wiki — captured in
  [`withsecure-chainsaw-shimcache.md`](./withsecure-chainsaw-shimcache.md)
  (https://github.com/WithSecureLabs/chainsaw/wiki/Shimcache-Analysis).
