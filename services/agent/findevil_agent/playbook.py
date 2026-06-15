"""Canonical DFIR detection rules, tool sequences, and self-score criteria.

This module is the single source of truth for:
- evidence-type detection (``detect_evidence_type``)
- artifact-class classification (``classify_artifact_path``)
- per-evidence-type tool sequences (``TOOL_SEQUENCES``)
- pre-submission self-assessment criteria (``JUDGE_SELFSCORE_CRITERIA``)

Both the interactive (Claude Code) path and the headless
(``scripts/find_evil_auto.py``) path import from here.  The in-VM
embedded script (which cannot import this package) receives these
rules serialised as a JSON argument instead.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# File-extension / name constants
# ---------------------------------------------------------------------------

MEMORY_EXTS: tuple[str, ...] = (".mem", ".raw", ".vmem", ".dmp", ".img", ".lime")
RAW_DISK_EXTS: tuple[str, ...] = (".e01", ".dd", ".aff", ".aff4", ".001")
YARA_TARGET_EXTS: tuple[str, ...] = (
    ".bat",
    ".cmd",
    ".dll",
    ".doc",
    ".docm",
    ".docx",
    ".exe",
    ".hta",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".vbe",
    ".vbs",
    ".xls",
    ".xlsm",
    ".xlsx",
)
REGISTRY_HIVE_NAMES: frozenset[str] = frozenset(
    {
        "software",
        "system",
        "security",
        "sam",
        "default",
        "ntuser.dat",
        "usrclass.dat",
        "amcache.hve",
    }
)


# ---------------------------------------------------------------------------
# PlaybookStep — one tool in a sequence
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlaybookStep:
    tool: str
    description: str
    pool: str  # "A", "B", or "both"
    optional: bool = False


# ---------------------------------------------------------------------------
# TOOL_SEQUENCES — canonical per-evidence-type investigation order
# ---------------------------------------------------------------------------

TOOL_SEQUENCES: dict[str, list[PlaybookStep]] = {
    "disk": [
        PlaybookStep("disk_mount", "Mount the disk image via libewf", pool="both"),
        PlaybookStep("disk_extract_artifacts", "Extract filesystem artifacts", pool="both"),
        PlaybookStep(
            "mft_timeline", "MFT timeline with timestomp detection ($SI vs $FN)", pool="both"
        ),
        PlaybookStep("usnjrnl_query", "UsnJrnl change log — file create/delete/rename", pool="A"),
        PlaybookStep("registry_query", "Run/RunOnce/IFEO/Services/WMI/Scheduled Tasks", pool="A"),
        PlaybookStep(
            "evtx_query", "Security/System/Application EVTX (EID 4624/4625/4688/7045)", pool="A"
        ),
        PlaybookStep(
            "hayabusa_scan", "Sigma rules over EVTX — persistence + lateral movement", pool="A"
        ),
        PlaybookStep(
            "prefetch_parse", "Prefetch execution evidence (cross-ref with memory PIDs)", pool="A"
        ),
        PlaybookStep("vel_collect", "Pull additional OS artifacts", pool="both", optional=True),
    ],
    "memory": [
        PlaybookStep("vol_pslist", "PsActiveProcessHead active-list walk", pool="both"),
        PlaybookStep(
            "vol_psscan", "EPROCESS pool scan — finds DKOM-unlinked processes", pool="both"
        ),
        PlaybookStep(
            "vol_psxview", "Cross-view comparison when pslist/psscan diverge", pool="both"
        ),
        PlaybookStep("vol_malfind", "VAD scan for injected PE regions", pool="both"),
        PlaybookStep("yara_scan", "YARA over memory dump", pool="both", optional=True),
    ],
    "evtx": [
        PlaybookStep("evtx_query", "Parse EVTX; pull EID histogram", pool="both"),
        PlaybookStep(
            "hayabusa_scan", "Sigma rule scan over EVTX directory", pool="A", optional=True
        ),
    ],
    "network": [
        PlaybookStep("pcap_triage", "C2 beacon / DNS / TLS JA3 fingerprints", pool="B"),
        PlaybookStep("zeek_summary", "Zeek conn/dns/http/ssl log summary", pool="B", optional=True),
        PlaybookStep(
            "sysmon_network_query", "Sysmon network events (EID 3/22)", pool="B", optional=True
        ),
    ],
    "velociraptor": [
        PlaybookStep("vel_collect", "Inventory the Velociraptor collection zip", pool="both"),
    ],
    "extracted_disk": [
        PlaybookStep("mft_timeline", "MFT timeline", pool="both", optional=True),
        PlaybookStep("prefetch_parse", "Prefetch execution evidence", pool="A", optional=True),
        PlaybookStep("registry_query", "Registry hive queries", pool="A", optional=True),
        PlaybookStep("usnjrnl_query", "UsnJrnl change log", pool="A", optional=True),
        PlaybookStep("browser_history", "Browser history databases", pool="B", optional=True),
        PlaybookStep(
            "ez_parse",
            "LNK, JumpList, Amcache, and Recycle Bin decoders",
            pool="both",
            optional=True,
        ),
        PlaybookStep(
            "plaso_parse",
            "Legacy EVT, IE history, task, and Recycle Bin timelines",
            pool="both",
            optional=True,
        ),
        PlaybookStep("yara_scan", "YARA over extracted executables", pool="both", optional=True),
    ],
    "directory": [
        PlaybookStep(
            "disk_extract_artifacts", "Classify and route artifacts in case directory", pool="both"
        ),
    ],
    "unknown": [],
}


# ---------------------------------------------------------------------------
# EVIDENCE_TYPE_RULES — coarse evidence-type from a path (no filesystem I/O)
# ---------------------------------------------------------------------------

# Each tuple: (predicate_key, evidence_type)
# Predicates are evaluated in order; first match wins.
# Used by detect_evidence_type() below.
EVIDENCE_TYPE_RULES: list[tuple[str, str]] = [
    ("memory_ext", "memory"),
    ("sysmon_evtx", "network"),
    ("evtx", "evtx"),
    ("pcap", "network"),
    ("raw_disk_ext", "disk"),
    ("zip", "velociraptor"),
]


def detect_evidence_type(path: str) -> str:
    """Return one of: directory, memory, evtx, disk, network, velociraptor, unknown.

    Pure function — no filesystem I/O.  For directory detection callers
    must check ``Path(path).is_dir()`` themselves before calling.
    """
    name = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    if name.endswith(MEMORY_EXTS):
        return "memory"
    if name.endswith(".evtx") and "sysmon" in name:
        return "network"
    if name.endswith(".evtx"):
        return "evtx"
    if name.endswith((".pcap", ".pcapng", ".cap")):
        return "network"
    if name.endswith(RAW_DISK_EXTS):
        return "disk"
    if name.endswith(".zip"):
        return "velociraptor"
    return "unknown"


# ---------------------------------------------------------------------------
# ARTIFACT_CLASS_RULES — fine-grained artifact/lane classification
# ---------------------------------------------------------------------------


def classify_artifact_path(path: str) -> dict[str, str | None]:
    """Classify a file path into a supported evidence/artifact lane.

    Returns a dict with keys: artifact_class, evidence_type, parser_tool.
    """
    # Normalise to forward slashes for cross-platform handling.
    norm = path.replace("\\", "/")
    name = norm.rsplit("/", 1)[-1].lower()
    lower_path = norm.lower()

    if name.endswith(MEMORY_EXTS):
        return {
            "artifact_class": "memory",
            "evidence_type": "memory",
            "parser_tool": "memory_playbook",
        }
    if name.endswith(".evtx") and "sysmon" in name:
        return {
            "artifact_class": "sysmon_network",
            "evidence_type": "network",
            "parser_tool": "sysmon_network_query",
        }
    if name.endswith(".evtx"):
        return {"artifact_class": "evtx", "evidence_type": "evtx", "parser_tool": "evtx_query"}
    if name.endswith((".pcap", ".pcapng", ".cap")):
        return {"artifact_class": "pcap", "evidence_type": "network", "parser_tool": "pcap_triage"}
    if name in {"conn.log", "dns.log", "http.log", "ssl.log", "tls.log"} or (
        name.endswith(".log") and "zeek" in lower_path
    ):
        return {"artifact_class": "zeek", "evidence_type": "network", "parser_tool": "zeek_summary"}
    if name.endswith(RAW_DISK_EXTS):
        return {"artifact_class": "raw_disk", "evidence_type": "disk", "parser_tool": None}
    if name in {"$mft", "mft"} or name.endswith(".mft"):
        return {
            "artifact_class": "mft",
            "evidence_type": "extracted_disk",
            "parser_tool": "mft_timeline",
        }
    if name.endswith(".pf"):
        return {
            "artifact_class": "prefetch",
            "evidence_type": "extracted_disk",
            "parser_tool": "prefetch_parse",
        }
    if name == "amcache.hve":
        return {
            "artifact_class": "amcache",
            "evidence_type": "extracted_disk",
            "parser_tool": "ez_parse",
        }
    if name in REGISTRY_HIVE_NAMES:
        return {
            "artifact_class": "registry",
            "evidence_type": "extracted_disk",
            "parser_tool": "registry_query",
        }
    if name == "srudb.dat":
        return {
            "artifact_class": "srum",
            "evidence_type": "extracted_disk",
            "parser_tool": None,
        }
    if (
        name in {"$j", "$usnjrnl", "usnjrnl", "usnjrnl.j"}
        or name.endswith(".usnjrnl")
        or name.endswith(".j")
        or "$extend/$usnjrnl" in lower_path
    ):
        return {
            "artifact_class": "usnjrnl",
            "evidence_type": "extracted_disk",
            "parser_tool": "usnjrnl_query",
        }
    if name.endswith(".evt"):
        return {
            "artifact_class": "legacy_evt",
            "evidence_type": "extracted_disk",
            "parser_tool": "plaso_parse",
        }
    if name.endswith(".lnk"):
        return {
            "artifact_class": "lnk",
            "evidence_type": "extracted_disk",
            "parser_tool": "ez_parse",
        }
    if name.endswith((".automaticdestinations-ms", ".customdestinations-ms")):
        return {
            "artifact_class": "jumplist",
            "evidence_type": "extracted_disk",
            "parser_tool": "ez_parse",
        }
    if name == "info2":
        return {
            "artifact_class": "recyclebin",
            "evidence_type": "extracted_disk",
            "parser_tool": "plaso_parse",
        }
    if name.startswith("$i") and "$recycle.bin" in lower_path:
        return {
            "artifact_class": "recyclebin",
            "evidence_type": "extracted_disk",
            "parser_tool": "ez_parse",
        }
    if name == "index.dat" and "history.ie5" in lower_path:
        return {
            "artifact_class": "ie_history",
            "evidence_type": "extracted_disk",
            "parser_tool": "plaso_parse",
        }
    if name == "thumbs.db" or name.endswith(".thumbcache"):
        return {
            "artifact_class": "thumbnail",
            "evidence_type": "extracted_disk",
            "parser_tool": None,
        }
    if name in {
        "history",
        "places.sqlite",
        "web data",
        "cookies",
        "login data",
    } or name.endswith(".sqlite"):
        return {
            "artifact_class": "browser_db",
            "evidence_type": "extracted_disk",
            "parser_tool": "browser_history",
        }
    if name.endswith(YARA_TARGET_EXTS):
        return {
            "artifact_class": "yara_target",
            "evidence_type": "extracted_disk",
            "parser_tool": "yara_scan",
        }
    if name.endswith(".zip"):
        return {
            "artifact_class": "velociraptor",
            "evidence_type": "velociraptor",
            "parser_tool": "vel_collect",
        }
    return {"artifact_class": "unknown", "evidence_type": "unknown", "parser_tool": None}


# ---------------------------------------------------------------------------
# JUDGE_SELFSCORE_CRITERIA — self-assessment criteria used by
# scripts/self-score.py (pre-submission grading)
# ---------------------------------------------------------------------------

JUDGE_SELFSCORE_CRITERIA: list[dict[str, str]] = [
    {
        "criterion": 1,
        "question": (
            "Did any tool call fail this run? If yes, did the audit log show "
            "explicit course-correction or verifier re-dispatch — and was the "
            "trigger natural or an injected fault?"
        ),
        "answer_style": "failures=N corrections=N redispatches=N injected_faults=N",
    },
    {
        "criterion": 2,
        "question": "What % of Findings are CONFIRMED vs INFERRED vs HYPOTHESIS?",
        "answer_style": "C=X% I=Y% H=Z%",
    },
    {
        "criterion": 3,
        "question": "How many artifact classes did this case touch? Which Findings cross >=2?",
        "answer_style": "classes=[…] crossed=[…]",
    },
    {
        "criterion": 4,
        "question": "Were any tool calls rejected by typed-surface validation this run?",
        "answer_style": "rejected=N reasons=[…]",
    },
    {
        "criterion": 5,
        "question": "Does every Finding cite a tool_call_id, and does each cited id resolve to a tool execution in the chain? (must be 100%; verifier vetoes otherwise)",
        "answer_style": "cited=N/N traced=N/N",
    },
    {
        "criterion": 6,
        "question": "Is the run reproducible from the manifest alone (no external state)?",
        "answer_style": "reproducible=yes/no",
    },
]
