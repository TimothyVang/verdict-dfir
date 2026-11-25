# Drive evidence helper

The helper downloads one cataloged VERDICT lab case from the shared Google Drive library. It is
path-agnostic, uses a local cache, and never sends a delete operation to Drive.

```bash
bash scripts/evidence-from-drive/pull-evidence.sh --list
CASE_DIR="$(bash scripts/evidence-from-drive/pull-evidence.sh win-lateral-movement)"
scripts/verdict "$CASE_DIR"
bash scripts/evidence-from-drive/pull-evidence.sh --evict win-lateral-movement
```

Defaults:

| Setting | Default |
|---|---|
| rclone remote | `verdictdrive` (`VERDICT_DRIVE_REMOTE`) |
| Local cache | `${XDG_CACHE_HOME:-$HOME/.cache}/verdict-evidence` (`EVIDENCE_CACHE`) |
| Catalog | `catalog.yaml` beside the helper (`CATALOG`) |

Configure the rclone remote with the `drive.readonly` OAuth scope and Drive root folder ID
`1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv`.

See [the full operator guide](../../docs/using/evidence-from-drive.md) for access, setup, case sizes,
cache controls, and troubleshooting.
