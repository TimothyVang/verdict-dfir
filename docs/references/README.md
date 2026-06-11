# `docs/references/` — external reference captures

Raw captures of the primary/authoritative sources surfaced by the deep-research
validation passes (see PR #17 and the research summaries). Each file carries a
provenance header (`source_url`, `retrieved`, `fetched_with`) and a `trust`
line.

**These are UNTRUSTED third-party captures.** They are stored verbatim for
claim substantiation and offline reference only. Copyright remains with each
original publisher. Always verify against the live source before relying on a
quote. Captured **2026-06-06** via [Scrapling](https://github.com/TimothyVang/Scrapling)
(`scrapling extract get --ai-targeted`, with noted exceptions).

## Index

| File | Source | Supports |
|---|---|---|
| `mandiant-shimcache.md` | Mandiant "Caching Out" (stub — see note below) | ShimCache is insertion-ordered NOT LRU; presence != execution |
| `withsecure-chainsaw-shimcache.md` | WithSecure Chainsaw wiki | Corroborates ShimCache findings above |
| `securelist-amcache.md` | Kaspersky GReAT / Securelist | Amcache `LastModified` != execution; insufficient alone |
| `sans-ntfs-attributes.md` | SANS DFIR | `$SI` vs `$FN` MACE timestamps; timestomp doctrine |
| `microsoft-event-4624-logon-types.md` | Microsoft Learn | 4624 Logon Type 3 = Network, Type 10 = RemoteInteractive |
| `microsoft-sysmon.md` | Microsoft Learn (Sysinternals) | Sysmon EID 1 `ProcessGuid` correlation key vs PID |
| `hayabusa.md` | Yamato Security | Sigma/Hayabusa hits are triage leads, not proof |
| `volatility3-psxview.md` | Volatility Foundation docs | psxview cross-view divergence = DKOM/T1014 |
| `cornell-lii-fre-902.md` | Cornell LII (rule text + Advisory Note) | FRE 902(14) = qualified-person hash certification (no timestamp prong) |
| `sigstore-trusted-time.md` | sigstore blog | Rekor as independent timestamp lower-bound (defense-in-depth) |
| `ietf-rfc9162-certificate-transparency.md` | IETF RFC 9162 (rfc-editor mirror) | Merkle inclusion-proof + signature construction |
| `mitre-t1218-signed-binary-proxy.md` | MITRE ATT&CK | LOLBin signed-binary-proxy-execution (rundll32/regsvr32/mshta) |
| `lolbas-regsvr32.md` | LOLBAS project | LOLBin abuse-function documentation |
| `mitre-t1547-001-run-keys.md` | MITRE ATT&CK | Persistence: Run/RunOnce keys |
| `mitre-t1543-003-windows-service.md` | MITRE ATT&CK | Persistence: Windows Service |
| `mitre-t1546-012-ifeo.md` | MITRE ATT&CK | Persistence: Image File Execution Options |
| `mitre-t1053-005-scheduled-task.md` | MITRE ATT&CK | Persistence: Scheduled Task |

## Capture caveats

- **`mandiant-shimcache.md` is a STUB.** The live Mandiant page is
  Cloudflare/JS-protected; plain HTTP returned only nav chrome. Scrapling's
  browser fetchers (`fetch` / `stealthy-fetch`) need Playwright system
  libraries that were not installable non-interactively on this host
  (`sudo playwright install-deps` would enable them). The
  WithSecure Chainsaw wiki capture corroborates the same findings.
- Files reflect each page's `--ai-targeted` main-content extraction; some
  residual site navigation may remain.
