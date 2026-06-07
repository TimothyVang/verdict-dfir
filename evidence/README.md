# Default evidence directory

This is the **default place to drop evidence** for a local Find Evil! run.
Run `bash scripts/find-evil-auto` with **no path argument** and the orchestrator
investigates whatever is here.

## How the default is resolved

`find-evil-auto` resolves the evidence path in this order:

1. An explicit path you pass: `bash scripts/find-evil-auto <path>`
2. `$FINDEVIL_EVIDENCE_ROOT` if that environment variable is set
3. Otherwise this directory (`evidence/`)

If you rely on the default (option 2 or 3), the directory must contain at least
one real evidence entry — a memory image, EVTX log, disk image, or a mixed case
folder. An empty directory (only this `README.md` / `.gitkeep`) produces a clear
error telling you to drop evidence in or pass a path.

## What to drop here

- A memory image (`.mem`, `.raw`, `.img`, `.vmem`, `.dmp`, `.lime`)
- A Windows event log (`.evtx`)
- A disk image (`.E01`, `.dd`, `.aff4`) — custody-registered; mount/extract for content
- A Velociraptor collection (`.zip`)
- A mixed **case folder** containing several of the above

## SIFT-VM mode is different

In SIFT-VM mode the evidence lives **inside the guest** (typically a VMware shared
folder at `/mnt/hgfs/evidence/`), and you pass that guest path explicitly:

```bash
bash scripts/find-evil-auto /mnt/hgfs/evidence/cases/<host>/ --unattended
```

This `evidence/` directory is the convenience default for **local-host** runs.

## Git

The directory is tracked (via this `README.md` and `.gitkeep`) so the convention
ships, but its **contents are gitignored** — evidence never enters the repo.
See the `/evidence/*` rule in `.gitignore`.
