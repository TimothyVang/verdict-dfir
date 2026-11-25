#!/usr/bin/env python3
"""Offline behavior smoke for scripts/evidence-from-drive/pull-evidence.sh.

The test harness supplies a temporary catalog and a fake ``rclone`` executable.
No network, real rclone configuration, or evidence corpus is required.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PULL_SCRIPT = REPO_ROOT / "scripts" / "evidence-from-drive" / "pull-evidence.sh"

CATALOG = """\
remote: verdictdrive
root_folder_id: "test-folder-id"
cases:
  dir-case:
    tier: small
    size_hint: ~1KiB
    remote_paths:
      - folders/dir-case/
    description: "Directory fixture"

  file-case:
    tier: small
    size_hint: ~2KiB
    remote_paths:
      - files/single.e01
    description: "Single-file fixture"
"""

FAKE_RCLONE = r"""#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
log_path = Path(os.environ["FAKE_RCLONE_LOG"])
with log_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(args) + "\n")

if args == ["listremotes"]:
    print(os.environ.get("FAKE_LISTREMOTES", "verdictdrive:"))
    raise SystemExit(0)

if args and args[0] == "lsf":
    if os.environ.get("FAKE_RCLONE_PROBE_FAIL") == "1":
        print("invalid_grant: token expired", file=sys.stderr)
        raise SystemExit(9)
    if os.environ.get("FAKE_RCLONE_WARN_ONLY") == "1":
        print("warning: transient backend notice", file=sys.stderr)
        raise SystemExit(0)
    if os.environ.get("FAKE_RCLONE_REMOTE_EMPTY") != "1":
        print("remote-evidence.bin")
    raise SystemExit(0)

if not args or args[0] != "copy":
    print("fake rclone only supports listremotes, lsf, and copy", file=sys.stderr)
    raise SystemExit(64)

if os.environ.get("FAKE_RCLONE_COPY_FAIL") == "1":
    print("invalid_grant: token expired", file=sys.stderr)
    raise SystemExit(9)

destination = Path(args[2])
destination.mkdir(parents=True, exist_ok=True)
if os.environ.get("FAKE_RCLONE_COPY_EMPTY") == "1":
    raise SystemExit(0)

if "--include" in args:
    output_name = args[args.index("--include") + 1]
else:
    output_name = "downloaded.bin"
(destination / output_name).write_bytes(b"test evidence\n")
"""


class EvidenceFromDriveSmoke(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.catalog = self.root / "catalog.yaml"
        self.catalog.write_text(CATALOG, encoding="utf-8")
        self.cache = self.root / "cache"
        self.log = self.root / "rclone-calls.jsonl"
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        fake_rclone = self.fake_bin / "rclone"
        fake_rclone.write_text(FAKE_RCLONE, encoding="utf-8")
        fake_rclone.chmod(0o755)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def env(self, *, with_rclone: bool = True) -> dict[str, str]:
        path_parts = ["/usr/bin", "/bin"]
        if with_rclone:
            path_parts.insert(0, str(self.fake_bin))
        return {
            **os.environ,
            "HOME": str(self.root / "home"),
            "PATH": os.pathsep.join(path_parts),
            "CATALOG": str(self.catalog),
            "EVIDENCE_CACHE": str(self.cache),
            "VERDICT_DRIVE_REMOTE": "verdictdrive",
            "FAKE_RCLONE_LOG": str(self.log),
        }

    def run_helper(
        self,
        *args: str,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(PULL_SCRIPT), *args],
            cwd=self.root,
            env=env or self.env(),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def rclone_calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]

    def test_help_and_no_args_work_without_rclone(self) -> None:
        for args in (("--help",), ()):
            with self.subTest(args=args):
                result = self.run_helper(*args, env=self.env(with_rclone=False))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Usage:", result.stdout)
        self.assertFalse(self.cache.exists())

    def test_list_is_offline_and_uses_the_catalog(self) -> None:
        result = self.run_helper("--list", env=self.env(with_rclone=False))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("dir-case", result.stdout)
        self.assertIn("file-case", result.stdout)
        self.assertEqual(self.rclone_calls(), [])

    def test_bad_arity_is_rejected(self) -> None:
        for args in (
            ("--evict",),
            ("--evict", "dir-case", "extra"),
            ("--list", "extra"),
            ("dir-case", "extra"),
        ):
            with self.subTest(args=args):
                result = self.run_helper(*args, env=self.env(with_rclone=False))
                self.assertEqual(result.returncode, 2)
                self.assertIn("Usage:", result.stderr)

    def test_invalid_and_unknown_ids_fail_before_rclone_preflight(self) -> None:
        for case_id in (".*", "../escape", ".hidden", "bad space"):
            with self.subTest(case_id=case_id):
                result = self.run_helper(case_id, env=self.env(with_rclone=False))
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid case-id", result.stderr)
                self.assertNotIn("rclone not on PATH", result.stderr)

        result = self.run_helper("unknown", env=self.env(with_rclone=False))
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown case-id", result.stderr)
        self.assertNotIn("rclone not on PATH", result.stderr)

    def test_evict_is_offline_and_preserves_siblings(self) -> None:
        target = self.cache / "dir-case"
        sibling = self.cache / "keep-me"
        target.mkdir(parents=True)
        sibling.mkdir()
        (target / "evidence.bin").write_bytes(b"delete me")
        (sibling / "evidence.bin").write_bytes(b"keep me")

        result = self.run_helper(
            "--evict",
            "dir-case",
            env=self.env(with_rclone=False),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(target.exists())
        self.assertTrue((sibling / "evidence.bin").exists())
        self.assertEqual(self.rclone_calls(), [])

    def test_evict_of_absent_case_does_not_create_cache(self) -> None:
        result = self.run_helper(
            "--evict",
            "dir-case",
            env=self.env(with_rclone=False),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nothing to evict", result.stderr)
        self.assertFalse(self.cache.exists())

    def test_evict_removes_retired_case_without_catalog_or_rclone(self) -> None:
        retired = self.cache / "retired-case"
        retired.mkdir(parents=True)
        (retired / "old-evidence.bin").write_bytes(b"old evidence")
        env = self.env(with_rclone=False)
        env["CATALOG"] = str(self.root / "missing.yaml")

        result = self.run_helper("--evict", "retired-case", env=env)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(retired.exists())
        self.assertEqual(self.rclone_calls(), [])

    def test_directory_pull_writes_metadata_and_returns_only_destination(self) -> None:
        result = self.run_helper("dir-case")
        destination = self.cache / "dir-case"

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(destination))
        self.assertTrue((destination / "downloaded.bin").exists())
        metadata = json.loads(
            (destination / "CASE_META.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["case_id"], "dir-case")
        self.assertEqual(metadata["remote"], "verdictdrive")
        self.assertEqual(metadata["remote_paths"], ["folders/dir-case/"])
        self.assertEqual(metadata["cache_root"], str(self.cache))

        calls = self.rclone_calls()
        self.assertEqual(calls[0], ["listremotes"])
        self.assertEqual(
            calls[1],
            [
                "lsf",
                "verdictdrive:folders/dir-case/",
                "--files-only",
                "--recursive",
            ],
        )
        self.assertEqual(
            calls[2],
            [
                "copy",
                "verdictdrive:folders/dir-case/",
                f"{destination}/",
                "--progress",
                "--transfers",
                "4",
            ],
        )
        self.assertNotIn(
            calls[2][0],
            {"delete", "deletefile", "move", "purge", "rmdir", "sync"},
        )

    def test_single_file_pull_uses_an_include_filter(self) -> None:
        result = self.run_helper("file-case")
        destination = self.cache / "file-case"

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((destination / "single.e01").exists())
        self.assertEqual(
            self.rclone_calls()[1],
            [
                "lsf",
                "verdictdrive:files",
                "--files-only",
                "--include",
                "single.e01",
            ],
        )
        self.assertEqual(
            self.rclone_calls()[2],
            [
                "copy",
                "verdictdrive:files",
                f"{destination}/",
                "--include",
                "single.e01",
                "--progress",
            ],
        )

    def test_metadata_treats_shell_values_as_data(self) -> None:
        quoted_cache = self.root / 'cache-"quoted'
        env = self.env()
        env["EVIDENCE_CACHE"] = str(quoted_cache)
        env["VERDICT_DRIVE_REMOTE"] = 'verdict"drive'
        env["FAKE_LISTREMOTES"] = 'verdict"drive:'

        result = self.run_helper("dir-case", env=env)

        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads(
            (quoted_cache / "dir-case" / "CASE_META.json").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["remote"], 'verdict"drive')
        self.assertEqual(metadata["cache_root"], str(quoted_cache))

    def test_empty_copy_fails_closed_without_metadata(self) -> None:
        env = self.env()
        env["FAKE_RCLONE_COPY_EMPTY"] = "1"

        result = self.run_helper("dir-case", env=env)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no evidence files", result.stderr)
        self.assertFalse((self.cache / "dir-case" / "CASE_META.json").exists())

    def test_repeated_pull_fails_if_remote_path_becomes_empty(self) -> None:
        first = self.run_helper("dir-case")
        self.assertEqual(first.returncode, 0, first.stderr)
        metadata_path = self.cache / "dir-case" / "CASE_META.json"
        original_metadata = metadata_path.read_bytes()
        env = self.env()
        env["FAKE_RCLONE_REMOTE_EMPTY"] = "1"

        second = self.run_helper("dir-case", env=env)

        self.assertNotEqual(second.returncode, 0)
        self.assertIn("remote path contains no files", second.stderr)
        self.assertTrue((self.cache / "dir-case" / "downloaded.bin").exists())
        self.assertEqual(metadata_path.read_bytes(), original_metadata)

    def test_probe_stderr_warning_is_not_mistaken_for_a_remote_file(self) -> None:
        first = self.run_helper("dir-case")
        self.assertEqual(first.returncode, 0, first.stderr)
        metadata_path = self.cache / "dir-case" / "CASE_META.json"
        original_metadata = metadata_path.read_bytes()
        env = self.env()
        env["FAKE_RCLONE_WARN_ONLY"] = "1"

        second = self.run_helper("dir-case", env=env)

        self.assertNotEqual(second.returncode, 0)
        self.assertIn("remote path contains no files", second.stderr)
        self.assertEqual(metadata_path.read_bytes(), original_metadata)

    def test_repeated_pull_succeeds_when_remote_is_nonempty_but_copy_is_current(
        self,
    ) -> None:
        first = self.run_helper("dir-case")
        self.assertEqual(first.returncode, 0, first.stderr)
        env = self.env()
        env["FAKE_RCLONE_COPY_EMPTY"] = "1"

        second = self.run_helper("dir-case", env=env)

        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertTrue((self.cache / "dir-case" / "downloaded.bin").exists())
        self.assertTrue((self.cache / "dir-case" / "CASE_META.json").exists())

    def test_copy_failure_has_actionable_auth_recovery(self) -> None:
        env = self.env()
        env["FAKE_RCLONE_COPY_FAIL"] = "1"

        result = self.run_helper("dir-case", env=env)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rclone copy failed", result.stderr)
        self.assertIn("rclone config reconnect", result.stderr)
        self.assertFalse((self.cache / "dir-case" / "CASE_META.json").exists())

    def test_remote_probe_failure_has_actionable_auth_recovery(self) -> None:
        env = self.env()
        env["FAKE_RCLONE_PROBE_FAIL"] = "1"

        result = self.run_helper("dir-case", env=env)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unable to list remote path", result.stderr)
        self.assertIn("rclone config reconnect", result.stderr)
        self.assertFalse((self.cache / "dir-case").exists())

    def test_pull_requires_rclone_and_the_named_remote(self) -> None:
        result = self.run_helper("dir-case", env=self.env(with_rclone=False))
        self.assertEqual(result.returncode, 1)
        self.assertIn("rclone not on PATH", result.stderr)

        env = self.env()
        env["FAKE_LISTREMOTES"] = "somewhere-else:"
        result = self.run_helper("dir-case", env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("is not configured", result.stderr)

    def test_catalog_is_required_for_every_operation(self) -> None:
        env = self.env(with_rclone=False)
        env["CATALOG"] = str(self.root / "missing.yaml")
        for args in (("--list",), ("dir-case",)):
            with self.subTest(args=args):
                result = self.run_helper(*args, env=env)
                self.assertEqual(result.returncode, 1)
                self.assertIn("catalog missing", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
