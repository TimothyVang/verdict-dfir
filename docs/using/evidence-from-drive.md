# Evidence from Google Drive

Download one lab case from the shared VERDICT evidence library into a local cache, run the case,
then optionally evict only that cached copy. Evidence remains outside git and the helper never
deletes or modifies the Google Drive library.

| | |
|---|---|
| Shared folder | [Open the VERDICT evidence library](https://drive.google.com/drive/folders/1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv?usp=sharing) |
| Folder ID | `1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv` |
| Helper | `scripts/evidence-from-drive/pull-evidence.sh` |
| Catalog | `scripts/evidence-from-drive/catalog.yaml` |
| Default cache | `${XDG_CACHE_HOME:-$HOME/.cache}/verdict-evidence/<case-id>/` |

## Access and permissions

Viewer or Commenter access can download by default; the owner or an organization policy can
disable downloading. Google documents the current role behavior in
[Share files from Google Drive](https://support.google.com/drive/answer/2494822).

You do not need Editor access. The setup below also gives rclone the `drive.readonly` OAuth scope,
which permits listing and downloading file content but not uploading, renaming, or deleting it.

## Quick path

After the one-time rclone setup below, run these commands from the root of a beta clone:

```bash
# This command reads the local catalog and does not contact Drive.
bash scripts/evidence-from-drive/pull-evidence.sh --list

# Pull one small EVTX case. The last stdout line is its absolute cache path.
CASE_DIR="$(bash scripts/evidence-from-drive/pull-evidence.sh win-lateral-movement)"

scripts/verdict "$CASE_DIR"

# Optional: remove only the local cached case.
bash scripts/evidence-from-drive/pull-evidence.sh --evict win-lateral-movement
```

`win-lateral-movement` is approximately 200 KiB and is the safest first download.

## One-time rclone setup

### 1. Confirm Drive access

1. Open the [shared folder](https://drive.google.com/drive/folders/1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv?usp=sharing).
2. Sign in with the Google account you will authorize in rclone.
3. Confirm that you can open the folder and see its contents.

If Google asks you to request access, complete that step before configuring rclone.

### 2. Install rclone

Use the platform instructions at [rclone.org/install](https://rclone.org/install/), then verify:

```bash
rclone version
```

### 3. Create the read-only remote

Run:

```bash
rclone config
```

Create a new remote with these values:

| Prompt | Value |
|---|---|
| New remote | `n` |
| Name | `verdictdrive` |
| Storage | Google Drive (`drive`) |
| Client ID / secret | Leave blank unless your organization requires its own OAuth client |
| Scope | `drive.readonly` |
| Root folder ID | `1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv` |
| Service account file | Leave blank for normal user login |
| Browser authorization | Sign in with the account that can open the shared folder |

The folder ID is the final segment of the shared folder URL. The read-only scope is sufficient for
`rclone lsd`, `rclone lsf`, and `rclone copy`.

Verify access:

```bash
rclone listremotes
rclone lsd verdictdrive:
```

The first command should show `verdictdrive:`. The second should list the library folders.

## Choose a case

The local catalog is authoritative for helper case IDs:

```bash
bash scripts/evidence-from-drive/pull-evidence.sh --list
```

### Small cases

| Case ID | Approximate size | Remote path |
|---|---:|---|
| `win-lateral-movement` | 200 KiB | `windows-event-logs/win-lateral-movement/` |
| `attack-samples` | 1.3 MiB | `windows-event-logs/attack-samples/` |
| `mini-fleet` | 1 MiB | `windows-event-logs/mini-fleet/` |
| `network-nitroba` | 48 MiB | `network-captures/nitroba/` |
| `security-datasets` | 76 MiB | `security-datasets/` |

### Large cases

Check free disk space before pulling these:

| Case ID | Approximate size | Remote path |
|---|---:|---|
| `nist-schardt` | 4 GiB | `disk-images/nist-hacking-case/` |
| `szechuan-dc` | 7 GiB | `mixed-cases/szechuan-dc/` |
| `rocba-fusion` | 18 GiB | `mixed-cases/rocba-fusion/` |
| `rocba-disk` | 23 GiB | `disk-images/rocba/rocba-cdrive.e01` |
| `magnet-ctf` | 38 GiB | `mixed-cases/magnet-ctf/` |
| `vanko` | 41 GiB | `mixed-cases/vanko/` |
| `srl-2018-derived` | 73 GiB | `derived-artifacts/srl-2018-xartifact/` |
| `srl-2018-memory-images` | 97 GiB | `memory-images/srl-2018/` |
| `srl-2018-disk-images` | 100 GiB | `disk-images/srl-2018/` |
| `rocba-memory` | Varies | `memory-images/rocba/Rocba-Memory.raw` |

Size hints are planning estimates, not integrity assertions. VERDICT fingerprints supplied evidence
when it opens a Case.

## Cache behavior

The default cache is outside the repository:

```text
${XDG_CACHE_HOME:-$HOME/.cache}/verdict-evidence/<case-id>/
```

Override it for another volume:

```bash
export EVIDENCE_CACHE=/mnt/forensics/verdict-evidence
```

For a temporary repo-local cache:

```bash
export EVIDENCE_CACHE="$(pwd)/.evidence-cache"
```

The repo-local `.evidence-cache/` path is gitignored. Other custom cache locations remain your
responsibility.

Each successful pull writes `CASE_META.json` with the case ID, remote name, pull time, remote paths,
and cache root. Before copying, the helper verifies that each cataloged remote path contains at
least one file. If the remote path or resulting case cache is empty, the helper fails without
replacing prior successful metadata. An up-to-date repeat pull can transfer zero bytes and still
succeed because the remote inventory and cached evidence are both present. Interrupted copies
retain partial local files so a later copy can resume.

## Safety contract

| Command | Contacts Drive? | Deletes remote data? | Deletes local data? |
|---|---:|---:|---:|
| `--help` | No | No | No |
| `--list` | No | No | No |
| `<case-id>` | Yes, using `rclone copy` | No | No |
| `--evict <case-id>` | No | No | Only that cache child |

Case IDs are restricted to letters, digits, underscores, and hyphens. The first character must be
alphanumeric. Pulls with unknown IDs and all commands with malformed IDs fail before rclone runs;
`--evict` can also remove a validly named retired cache entry that is no longer in the catalog.

The helper never calls `rclone sync`, `move`, `delete`, or `purge`.

## Browser-only fallback

For a few small files, open the shared folder, download the desired folder through the browser, and
point VERDICT at the saved path:

```bash
scripts/verdict /path/to/downloaded/evidence
```

Use rclone for large cases because retries and incremental copies are easier to manage.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `rclone not on PATH` | Install rclone and rerun `rclone version`. |
| Remote is not configured | Run `rclone config` and create `verdictdrive` with the folder ID above. |
| `invalid_grant` or expired token | Run `rclone config reconnect verdictdrive:` and authorize the same Google account again. |
| Permission denied | Open the share link with the authorized account and confirm downloads are allowed. |
| Empty or missing path | Run `rclone lsf verdictdrive:<remote-path>` and compare it with `catalog.yaml`. |
| Unknown case ID | Run the offline `--list` command and use an exact catalog ID. |
| Disk full | Choose a small case, change `EVIDENCE_CACHE`, or evict an old cached case. |
| `scripts/verdict` not found | Run from a beta clone or invoke that script by its resolved clone path. |

If a configured remote points to a mirror instead, set its name without changing the script:

```bash
export VERDICT_DRIVE_REMOTE=my-readonly-mirror
```

## Related documentation

- [Evidence Intake](evidence-intake.md)
- [Running VERDICT](running-verdict.md)
- [Quickstart](https://github.com/TimothyVang/verdict-dfir-beta/blob/main/QUICKSTART.md)
- [Dataset notes](../DATASET.md)
