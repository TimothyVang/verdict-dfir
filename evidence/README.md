# `evidence/` — drop your case files here

> This is the README for the **`evidence/` folder**, not the project README.
> Project overview is the repo-root [`README.md`](../README.md); the 3-step start
> is [`QUICKSTART.md`](../QUICKSTART.md).

This is the **default place to drop evidence** for a local Find Evil! run. Put a
file (or a case folder) here, then run one of:

```bash
bash scripts/verdict --watch     # waits for a drop, then investigates automatically
bash scripts/verdict evidence/   # investigate everything currently here
```

…or, in a Claude Code session (`claude` in the repo):

```
investigate evidence/
```

## What to drop here

- A memory image (`.mem`, `.raw`, `.img`, `.vmem`, `.dmp`, `.lime`)
- A Windows event log (`.evtx`)
- A disk image (`.E01`, `.dd`, `.aff4`) — custody-registered; mount/extract for content
- A network capture (`.pcap`, `.pcapng`)
- A Velociraptor collection (`.zip`)
- A mixed **case folder** containing several of the above

## How the default path is resolved

When you don't pass an explicit path, the engine looks here in order:

1. An explicit path you pass: `bash scripts/verdict <path>`
2. `$FINDEVIL_EVIDENCE_ROOT` if that environment variable is set
3. Otherwise this directory (`evidence/`)

An empty `evidence/` (only this `README.md` / `.gitkeep`) produces a clear error
telling you to drop evidence in or pass a path.

## SIFT-VM mode is different

In SIFT-VM mode the evidence lives **inside the guest** (typically a VMware shared
folder at `/mnt/hgfs/evidence/`), and you pass that guest path explicitly:

```bash
bash scripts/verdict --sift /mnt/hgfs/evidence/cases/<host>/ --unattended
```

This `evidence/` directory is the convenience default for **local-host** runs.

## Git

The directory is tracked (via this `README.md` and `.gitkeep`) so the convention
ships, but its **contents are gitignored** — evidence never enters the repo. See
the `/evidence/*` rule in `.gitignore`.
