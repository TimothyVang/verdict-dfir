"""Self-contained interactive collapsible process-tree HTML fragment.

Presentation only: this renders ``model.procs`` as a navigable
``<details>``/``<summary>`` forest with a tiny inline filter/expand toolbar.
No external CSS/JS/fonts — safe to embed in the report or open standalone.
Deterministic: no randomness or wall-clock time, stable pid-ordered output.
"""

from __future__ import annotations

import re
from html import escape

from .model import AttackFlowModel, ProcNode

_INK = "#101426"
_CREAM = "#F5F1E8"
_COBALT = "#4D5DFF"
_CORAL = "#FF6257"
_CORAL_TINT = "#FFE1DE"

_STYLE = f"""
<style>
.pt-root {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  color: {_INK};
  background: {_CREAM};
  border-radius: 8px;
  padding: 1rem 1.25rem;
  font-size: 13px;
  line-height: 1.4;
}}
.pt-root .pt-header {{
  font-weight: 600;
  margin-bottom: 0.25rem;
}}
.pt-root .pt-note {{
  opacity: 0.65;
  font-size: 11px;
  margin-bottom: 0.75rem;
}}
.pt-root .pt-toolbar {{
  display: flex;
  gap: 0.5rem;
  align-items: center;
  margin-bottom: 0.75rem;
  flex-wrap: wrap;
}}
.pt-root .pt-toolbar input[type="text"] {{
  flex: 1 1 auto;
  min-width: 8rem;
  padding: 0.3rem 0.5rem;
  border-radius: 6px;
  border: 1px solid rgba(16,20,38,0.25);
  background: rgba(255,255,255,0.6);
  color: {_INK};
  font-size: 12px;
}}
.pt-root .pt-toolbar button {{
  padding: 0.3rem 0.6rem;
  border-radius: 6px;
  border: 1px solid {_COBALT};
  background: {_COBALT};
  color: #fff;
  font-size: 12px;
  cursor: pointer;
}}
.pt-root .pt-toolbar button:hover {{
  filter: brightness(1.08);
}}
.pt-root details {{
  margin-left: 0.9rem;
}}
.pt-root details > summary {{
  cursor: pointer;
  list-style: none;
  padding: 0.1rem 0.3rem;
  border-radius: 4px;
}}
.pt-root details > summary::-webkit-details-marker {{
  display: none;
}}
.pt-root details > summary:before {{
  content: "\\25B8";
  display: inline-block;
  margin-right: 0.3rem;
  transition: transform 0.12s ease;
}}
.pt-root details[open] > summary:before {{
  transform: rotate(90deg);
}}
.pt-root .pt-leaf {{
  margin-left: 0.9rem;
  padding: 0.1rem 0.3rem;
}}
.pt-root .pt-pid {{
  opacity: 0.6;
  font-size: 11px;
}}
.pt-root .flagged > summary,
.pt-root .pt-leaf.flagged {{
  background: {_CORAL_TINT};
  border-left: 3px solid {_CORAL};
}}
.pt-root .pt-tag {{
  display: inline-block;
  margin-left: 0.4rem;
  padding: 0 0.35rem;
  border-radius: 999px;
  background: {_CORAL};
  color: #fff;
  font-size: 10px;
  font-weight: 600;
  vertical-align: middle;
}}
.pt-root .pt-hidden {{
  display: none !important;
}}
@media (prefers-color-scheme: dark) {{
  .pt-root {{
    background: #171b2e;
    color: {_CREAM};
  }}
  .pt-root .pt-toolbar input[type="text"] {{
    background: rgba(255,255,255,0.08);
    border-color: rgba(245,241,232,0.25);
    color: {_CREAM};
  }}
}}
@media (prefers-reduced-motion: reduce) {{
  .pt-root details > summary:before {{
    transition: none;
  }}
}}
</style>
""".strip()

# Toolbar script is scoped to each .pt-root instance so multiple trees on one
# page (report + standalone view) never collide.
_SCRIPT_TEMPLATE = """
<script>
(function () {{
  var root = document.getElementById("{root_id}");
  if (!root) return;
  var filterBox = root.querySelector(".pt-filter");
  var expandBtn = root.querySelector(".pt-expand-all");
  var collapseBtn = root.querySelector(".pt-collapse-all");
  var rows = root.querySelectorAll("[data-pt-match]");

  function applyFilter() {{
    var q = (filterBox && filterBox.value || "").trim().toLowerCase();
    rows.forEach(function (row) {{
      if (!q) {{
        row.classList.remove("pt-hidden");
        return;
      }}
      var hay = (row.getAttribute("data-pt-match") || "").toLowerCase();
      var match = hay.indexOf(q) !== -1;
      row.classList.toggle("pt-hidden", !match);
      if (match) {{
        var d = row.closest("details");
        while (d) {{
          d.open = true;
          d = d.parentElement ? d.parentElement.closest("details") : null;
        }}
      }}
    }});
  }}

  if (filterBox) {{
    filterBox.addEventListener("input", applyFilter);
  }}
  if (expandBtn) {{
    expandBtn.addEventListener("click", function () {{
      root.querySelectorAll("details").forEach(function (d) {{ d.open = true; }});
    }});
  }}
  if (collapseBtn) {{
    collapseBtn.addEventListener("click", function () {{
      root.querySelectorAll("details").forEach(function (d) {{ d.open = false; }});
    }});
  }}
}})();
</script>
""".strip()


def _forest(procs: list[ProcNode]) -> tuple[dict[int, list[ProcNode]], list[ProcNode]]:
    """Group children by parent pid; return (children_by_ppid, roots) both pid-sorted."""
    pids = {p.pid for p in procs}
    children: dict[int, list[ProcNode]] = {}
    roots: list[ProcNode] = []
    for p in procs:
        if p.ppid is not None and p.ppid in pids and p.ppid != p.pid:
            children.setdefault(p.ppid, []).append(p)
        else:
            roots.append(p)
    for lst in children.values():
        lst.sort(key=lambda p: p.pid)
    roots.sort(key=lambda p: p.pid)
    return children, roots


def _ancestor_pids_of_flagged(
    children: dict[int, list[ProcNode]], procs: list[ProcNode]
) -> set[int]:
    """Pids of every ancestor of a flagged process, computed deterministically."""
    parent_of: dict[int, int] = {}
    for ppid, kids in children.items():
        for k in kids:
            parent_of[k.pid] = ppid
    ancestors: set[int] = set()
    for p in procs:
        if not p.linked_action_ids:
            continue
        cur = parent_of.get(p.pid)
        seen: set[int] = set()
        while cur is not None and cur not in seen:
            ancestors.add(cur)
            seen.add(cur)
            cur = parent_of.get(cur)
    return ancestors


def _row_match_text(p: ProcNode) -> str:
    return escape(f"{p.image_name or '?'} {p.pid}")


def _render_node(p: ProcNode, children: dict[int, list[ProcNode]], expand_pids: set[int]) -> str:
    kids = children.get(p.pid, [])
    flagged = bool(p.linked_action_ids)
    name = escape(p.image_name or "?")
    match_text = _row_match_text(p)
    tag = '<span class="pt-tag">linked to finding</span>' if flagged else ""
    ppid_text = f" &middot; ppid {p.ppid}" if p.ppid is not None else ""
    label = f'{name} <span class="pt-pid">pid {p.pid}{ppid_text}</span>{tag}'

    if not kids:
        cls = "pt-leaf flagged" if flagged else "pt-leaf"
        return f'<div class="{cls}" data-pt-match="{match_text}">{label}</div>'

    open_attr = " open" if (flagged or p.pid in expand_pids) else ""
    cls = "flagged" if flagged else ""
    body = "".join(_render_node(k, children, expand_pids) for k in kids)
    return (
        f'<details class="{cls}"{open_attr} data-pt-match="{match_text}">'
        f"<summary>{label}</summary>{body}</details>"
    )


def process_tree_html(model: AttackFlowModel) -> str:
    """Render the process forest as a self-contained interactive HTML fragment."""
    if model.proc_source == "none" or not model.procs:
        reason = escape(model.proc_reason or "no process-lineage artifact in this case")
        return (
            '<div class="pt-root">'
            '<div class="pt-header">Process tree unavailable</div>'
            f"<div class='pt-note'>{reason}</div>"
            "</div>"
        )

    children, roots = _forest(model.procs)
    expand_pids = _ancestor_pids_of_flagged(children, model.procs)
    # Slug the case_id: it lands in an HTML id AND a JS getElementById literal,
    # so restrict to id-safe chars rather than relying on html-escape's incidental
    # JS-safety.
    root_id = "pt-" + (re.sub(r"[^A-Za-z0-9_-]", "", model.case_id or "") or "case")
    body = "".join(_render_node(r, children, expand_pids) for r in roots)
    header = f"{len(model.procs)} processes &middot; {escape(model.proc_source)} &middot; {escape(model.case_id or '')}"

    return (
        f'<div class="pt-root" id="{root_id}">'
        f'<div class="pt-header">{header}</div>'
        '<div class="pt-note">Presentation only — not a Finding; see the linked-action list for cited evidence.</div>'
        '<div class="pt-toolbar">'
        '<input type="text" class="pt-filter" placeholder="Filter by process name or pid" '
        'aria-label="Filter processes">'
        '<button type="button" class="pt-expand-all">Expand all</button>'
        '<button type="button" class="pt-collapse-all">Collapse all</button>'
        "</div>"
        f'<div class="pt-tree">{body}</div>'
        f"{_STYLE}"
        f"{_SCRIPT_TEMPLATE.format(root_id=root_id)}"
        "</div>"
    )
