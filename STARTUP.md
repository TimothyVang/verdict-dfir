# Team Startup — SANS Find Evil! 2026

New-member onboarding. Do all of these in order. Source: PUG's kickoff message.

---

## What this hackathon is

**Protocol SIFT** integrates AI agents with the **SANS SIFT Workstation** — 200+ incident response tools on a single platform — through the **Model Context Protocol (MCP)**. An analyst types what they need in natural language; the AI selects tools, executes them, reasons about the output, and produces structured reports.

The community's mission: **sharpen this proof of concept into a production-grade capability.**

**Final deadline: 2026-06-15 22:45 CDT.**

---

## Step 1 — Join the Devpost team

**Team join link:** https://devpost.com/software/1252743/joins/EhwI8bQ5t7upeQ_l3fT5RQ

1. Create a free Devpost account if you don't have one: https://devpost.com/
2. Click the team join link above while logged in.
3. Accept the invitation.
4. Confirm your name appears on the team's submission page.
5. Screenshot it and post in team chat so the lead can confirm.

This adds you to the submission roster only. Code access + SIFT VM are separate steps below.

---

## Step 2 — Download the SANS SIFT Workstation

**SANS SIFT Workstation:** https://sans.org/tools/sift-workstation

1. Go to the link, scroll to the **VM** option, and download the OVA file (~9 GB).
2. Save it to a known location (e.g. `C:\VMs\sift-2026.03.24.ova` on Windows).
3. SIFT runs in any major hypervisor; **VMware Workstation Pro 17** is the SANS-blessed path. VirtualBox 7 also works.
4. Import the OVA into your hypervisor:
   - Bump RAM to 8 GB, CPUs to 4
   - Network adapter: NAT
   - Add a shared folder for your evidence directory (e.g. host `C:\evidence` → VM `/mnt/hgfs/evidence`)
5. Power on. Default credentials: `sansforensics` / `forensics`.
6. **Take a VM snapshot** named `clean-install` so you can revert between investigations.

---

## Step 3 — Install Protocol SIFT

Once SIFT is up and running, **inside the SIFT VM**:

```bash
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
```

This installs the Protocol SIFT POC — the FastMCP gateway, starter skills/playbooks, and config that lets a Claude Code (or other MCP client) session call SIFT tools.

Take another VM snapshot named `protocol-sift-installed` after it succeeds.

---

## Step 4 — Get the starter case data

**Starter case data (sample disk images + memory captures):**
https://sansorg.egnyte.com/fl/HhH7crTYT4JK

1. Download to your **host** machine (the shared folder makes it visible inside the VM).
2. Recommended host path: `C:\evidence\hackathon-2026\` → visible in VM as `/mnt/hgfs/evidence/hackathon-2026/`.
3. Verify SHA-256 of every file you downloaded — you'll cite these in the audit chain.
4. Treat all case files as **read-only**. Never modify them in place.

---

## Step 5 — Read the reference materials

Before you start building, skim these. Each one shapes a different part of the project.

### Q&A source (use this first when stuck)
- **Protocol SIFT NotebookLM notebook:**
  https://notebooklm.google.com/notebook/f0957a60-6fb2-452b-93d4-ecd73ba47779?authuser=1
  This is the **chief location for asking questions** about how/what to build. Use it before guessing.

### Reference quality bar
- **Valhuntir** (Steve Anson, SANS Author):
  https://github.com/AppliedIR/Valhuntir
  Example submission demonstrating the level of quality to **meet or exceed**. AI-augmented incident response platform. Read the README, browse the architecture, note the polish.

### Inspiration / "why now"
- **SANS blog:** *Protocol SIFT: An Experimental Research Initiative for AI-Assisted DFIR* — sans.org
- **Rob T. Lee's Substack:** *Introducing Protocol SIFT: Meeting AI Threat Speed with Defensive AI Orchestration*
- **Anthropic GTG-1002 threat intelligence report** — the offensive operation that validates why Protocol SIFT matters. The defensive case in one report.

---

## Step 6 — Get the team's code
I will add you to the github repo

---

## Step 7 — Run your first investigation

From inside the SIFT VM, the simplest path:

```bash
cd ~
claude                                  # opens an interactive Claude Code session
> investigate /mnt/hgfs/evidence/hackathon-2026/<case-folder>
```

The agent will load its identity prompts, open the case, run DFIR tools, emit Findings citing tool call IDs, judge them, and produce a structured report.

If you got the team's repo in Step 6, you also have the one command — `scripts/verdict <evidence>` (preflight → investigate → open the live dashboard → signed verdict + report). Use that for headless runs; the interactive `investigate <case>` above is the same workflow driven by hand.

---

## Quick checklist (copy this into your notes)

- [ ] Devpost account created
- [ ] Joined the team via the Devpost link
- [ ] Confirmed name on team page, screenshot posted in chat
- [ ] SIFT OVA downloaded and imported into hypervisor
- [ ] SIFT VM boots; snapshot `clean-install` taken
- [ ] Protocol SIFT installed via the curl command
- [ ] Snapshot `protocol-sift-installed` taken
- [ ] Starter case data downloaded from Egnyte and visible inside VM
- [ ] NotebookLM bookmarked
- [ ] Valhuntir README read end-to-end
- [ ] SANS blog + Rob Lee Substack + GTG-1002 report skimmed
- [ ] Team code received from PUG
- [ ] First `investigate <case>` run completed successfully

---

## Who to contact

- **Team lead:** PUG / TSgt Timothy Vang — for code access, technical questions, task pairing
- **Devpost platform issues:** https://help.devpost.com/

Welcome to the team.
