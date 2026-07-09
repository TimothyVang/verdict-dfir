#!/usr/bin/env python3
"""Verify the documented product tool count matches registered MCP tools."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import NamedTuple


REPO = Path(__file__).resolve().parent.parent
DEFAULT_EXPECTED_RUST = 32
DEFAULT_EXPECTED_PYTHON = 14


class DocRule(NamedTuple):
    path: str
    requires_total: bool = False
    requires_rust: bool = False
    requires_python: bool = False
    # Optional docs are checked only when present (e.g. a gitignored local
    # draft); an absent optional doc is skipped instead of failing the guard.
    optional: bool = False


DOC_RULES = (
    DocRule("CLAUDE.md", requires_total=True, requires_rust=True, requires_python=True),
    DocRule("README.md", requires_total=True, requires_rust=True, requires_python=True),
    DocRule(
        "INSTALL.md", requires_total=True, requires_rust=True, requires_python=True
    ),
    DocRule(
        "docs/architecture.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule(
        "docs/reference/mcp-and-tools.md",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    DocRule(
        "scripts/make-demo-video/src/components/ArchPoster.tsx",
        requires_total=True,
        requires_rust=True,
        requires_python=True,
    ),
    # Strategy doc (gitignored local draft) — pin only the VERDICT product-total
    # claim. It is freeform prose citing many rivals' tool counts, so requiring
    # the Rust/Python sub-counts would false-positive on competitor descriptions;
    # requires_total catches the "56 product tools" drift that this guard missed.
    # optional=True: the file is gitignored, so CI runs without it — check it
    # when the local draft is present, skip when absent.
    DocRule("docs/competitive-analysis.md", requires_total=True, optional=True),
)


def _extract_braced_block(text: str, marker: str) -> str:
    marker_index = text.find(marker)
    if marker_index == -1:
        raise ValueError(f"missing marker {marker!r}")
    brace_index = text.find("{", marker_index)
    if brace_index == -1:
        raise ValueError(f"missing opening brace after {marker!r}")

    depth = 0
    for index in range(brace_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[brace_index : index + 1]
    raise ValueError(f"missing closing brace after {marker!r}")


def count_rust_tools(root: Path = REPO) -> int:
    server_rs = root / "services/mcp/src/server.rs"
    body = _extract_braced_block(
        server_rs.read_text(encoding="utf-8"),
        "fn build_registry()",
    )
    return len(re.findall(r'\bname:\s*"[^"]+"', body))


def count_python_tools(root: Path = REPO) -> int:
    registry = root / "services/agent_mcp/findevil_agent_mcp/tools/__init__.py"
    module = ast.parse(registry.read_text(encoding="utf-8"), filename=str(registry))
    for node in module.body:
        value = None
        if isinstance(node, ast.AnnAssign) and _is_modules_target(node.target):
            value = node.value
        elif isinstance(node, ast.Assign) and any(
            _is_modules_target(t) for t in node.targets
        ):
            value = node.value
        if isinstance(value, ast.Tuple):
            return sum(
                isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                for elt in value.elts
            )
    raise ValueError("missing _MODULES tuple in Python MCP tool registry")


def _is_modules_target(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "_MODULES"


def _required_count_errors(
    text: str, rule: DocRule, total: int, rust: int, python: int
) -> list[str]:
    errors = []
    checks = (
        (rule.requires_total, total, "product total"),
        (rule.requires_rust, rust, "Rust count"),
        (rule.requires_python, python, "Python count"),
    )
    for required, expected, label in checks:
        if required and str(expected) not in text:
            errors.append(f"{rule.path}: missing {label} {expected}")
        if required:
            errors.extend(_conflicting_count_errors(text, rule.path, expected, label))
    return errors


COUNT_CLAIM_PATTERNS = {
    "product total": (
        re.compile(r"\b(\d+)\s+(?:audit-chained\s+)?product\s+tools\b"),
        re.compile(r"\b(\d+)\s+typed\s+read-only\s+tools\b"),
        re.compile(r"\b(\d+)\s+narrow\s+schema-validated\s+product\s+tools\b"),
    ),
    "Rust count": (
        re.compile(r"\b(\d+)\s+Rust(?:\s+DFIR)?(?:\s+MCP)?\s+tools\b"),
        re.compile(r"findevil-mcp[^\n|]*\b(\d+)\s+DFIR\s+tools\b"),
    ),
    "Python count": (
        re.compile(r"\b(\d+)\s+Python[^\n|]*\btools\b"),
        re.compile(
            r"findevil-agent-mcp[^\n|]*\b(\d+)\s+crypto/ACH/memory[^\n|]*tools\b"
        ),
    ),
}


def _conflicting_count_errors(
    text: str, path: str, expected: int, label: str
) -> list[str]:
    patterns = COUNT_CLAIM_PATTERNS[label]
    errors = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            actual = int(match.group(1))
            if actual != expected:
                errors.append(f"{path}: {label} claim {actual} != {expected}")
    return errors


def validate_docs(root: Path, rust: int, python: int) -> list[str]:
    total = rust + python
    errors = []
    for rule in DOC_RULES:
        path = root / rule.path
        if not path.is_file():
            if not rule.optional:
                errors.append(f"{rule.path}: missing monitored documentation file")
            continue
        text = path.read_text(encoding="utf-8")
        errors.extend(_required_count_errors(text, rule, total, rust, python))
    return errors


def validate_counts(
    root: Path = REPO,
    *,
    expected_rust: int = DEFAULT_EXPECTED_RUST,
    expected_python: int = DEFAULT_EXPECTED_PYTHON,
) -> list[str]:
    errors = []
    rust = count_rust_tools(root)
    python = count_python_tools(root)
    if rust != expected_rust:
        errors.append(f"Rust registry has {rust} tools; expected {expected_rust}")
    if python != expected_python:
        errors.append(f"Python registry has {python} tools; expected {expected_python}")
    errors.extend(validate_docs(root, rust, python))
    return errors


def main() -> int:
    errors = validate_counts(REPO)
    if errors:
        print("FAIL - tool-count guard found inconsistent tool surface docs:")
        for error in errors:
            print(f"  - {error}")
        return 1

    rust = count_rust_tools(REPO)
    python = count_python_tools(REPO)
    print(
        "OK - tool surface count matches code and docs: "
        f"{rust + python} product tools ({rust} Rust + {python} Python)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
