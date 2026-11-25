#!/usr/bin/env python3
"""codegen-events — regenerate ``apps/web/lib/events.ts`` from
``services/agent/findevil_agent/events.py``.

Per A3 plan Task 4.3 + the ``events.py`` module docstring.

Bypasses ``pydantic2ts`` because pydantic2ts 2.0.0 hardcodes
``--bannerComment ""`` (empty string) when invoking json2ts, which
prettier 3.8.x in ``json-schema-to-typescript`` 14.x/15.x can't
parse — every codegen attempt errors with a useless "exit code 1"
on a fresh install. We do the same job in two steps the codegen
controls cleanly:

1. Pydantic v2's ``models_json_schema`` builds the JSON schema for
   every BaseModel in the module, with proper ``$defs`` references.
2. ``apps/web/node_modules/.bin/json2ts`` (the real CLI; Windows
   ``.CMD`` resolved first then bare) consumes the schema and emits
   TypeScript. No banner comment is passed.

Run from the repo root::

    uv run --directory services/agent python ../../scripts/codegen-events.py

Pre-flight:
    - ``uv sync --directory services/agent --extra dev`` (Pydantic v2)
    - ``pnpm install``                                   (json2ts in apps/web/node_modules/.bin)

Output (``apps/web/lib/events.ts``) is committed — the dashboard
build does not depend on a Python toolchain at runtime; the file
gets regenerated whenever ``events.py`` changes shape.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from importlib import import_module
from pathlib import Path

from pydantic import BaseModel
from pydantic.json_schema import models_json_schema


def main() -> int:
    repo = Path(__file__).resolve().parent.parent

    # --- 1. Discover every Pydantic model in findevil_agent.events.
    module = import_module("findevil_agent.events")
    models: list[type[BaseModel]] = [
        cls
        for name, cls in vars(module).items()
        if isinstance(cls, type)
        and issubclass(cls, BaseModel)
        and cls is not BaseModel
        # Skip private bases (_BaseEvent etc.) to keep the TS
        # surface clean.
        and not name.startswith("_")
    ]
    if not models:
        print(
            "ERROR: no Pydantic models found in findevil_agent.events", file=sys.stderr
        )
        return 1

    # --- 2. Generate the unified JSON schema.
    # `models_json_schema` is the Pydantic v2 multi-model entry point;
    # it merges per-model `$defs` into a single doc with `definitions`-
    # style refs that json2ts understands.
    _, schema = models_json_schema(
        [(m, "validation") for m in models],
        title="AgentEvent",
        ref_template="#/definitions/{model}",
    )
    # json2ts expects "definitions"; Pydantic v2 emits "$defs" by default.
    if "$defs" in schema:
        schema["definitions"] = schema.pop("$defs")
    # Make the top-level a `oneOf` discriminated union of every event
    # so json2ts emits (a) one interface per model and (b) a top-level
    # `AgentEvent = ToolCallStart | ToolCallOutput | …` type alias.
    # Without this, json2ts only emits interfaces for definitions
    # reachable from the top-level — which would be none, leaving the
    # output essentially empty.
    # Only event variants (those with an ``event_type`` discriminator) belong
    # in the AgentEvent union. Nested value models like ``PriorObservation``
    # still get a TS interface (they're reachable via the events that embed
    # them) but must not become union members.
    schema["oneOf"] = [
        {"$ref": f"#/definitions/{m.__name__}"}
        for m in models
        if "event_type" in m.model_fields
    ]
    schema["title"] = "AgentEvent"
    schema.pop("type", None)

    # --- 3. Resolve json2ts (Windows .CMD or bare).
    json2ts_dir = repo / "apps" / "web" / "node_modules" / ".bin"
    candidates: list[Path]
    if os.name == "nt":
        candidates = [json2ts_dir / "json2ts.CMD", json2ts_dir / "json2ts"]
    else:
        candidates = [json2ts_dir / "json2ts"]
    json2ts = next((c for c in candidates if c.exists()), None)
    if json2ts is None:
        print(
            f"ERROR: json2ts not found in {json2ts_dir}.\n"
            "Run 'pnpm install' from the repo root to fetch the "
            "json-schema-to-typescript devDep.",
            file=sys.stderr,
        )
        return 1

    # --- 4. Write schema to a temp file, invoke json2ts, capture output.
    output_path = repo / "apps" / "web" / "lib" / "events.ts"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(schema, f, indent=2)
        schema_path = f.name

    try:
        result = subprocess.run(
            [str(json2ts), "-i", schema_path, "-o", str(output_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        os.unlink(schema_path)

    if result.returncode != 0:
        print("json2ts failed:", file=sys.stderr)
        if result.stdout:
            print(result.stdout, file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        return result.returncode

    # --- 5. Prepend a repo-specific banner so the file is unmistakably
    # generated. Done in Python (not via json2ts --bannerComment) to
    # avoid the prettier-can't-parse-empty-banner footgun that pushed
    # us off pydantic2ts in the first place.
    banner = (
        "// AUTO-GENERATED by scripts/codegen-events.py from\n"
        "// services/agent/findevil_agent/events.py. DO NOT EDIT BY\n"
        "// HAND — re-run the codegen instead. Per A3 plan Task 4.3.\n"
        "\n"
    )
    body = output_path.read_text(encoding="utf-8")
    output_path.write_text(banner + body, encoding="utf-8")

    line_count = len(body.splitlines()) + len(banner.splitlines())
    print(f"wrote {output_path}  ({len(models)} models, {line_count} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
