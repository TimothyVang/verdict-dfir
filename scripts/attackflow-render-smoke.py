#!/usr/bin/env python3
"""Render/interaction smoke: drive the emitted HTML in a real headless browser.

The structure-only tests verify markup is present; they do NOT verify that things
actually RENDER or that the interactions WORK. Every real visual bug this feature
hit (invisible node labels, a doubled process tree, a dead brush) passed those
tests and was only caught by looking. This smoke closes that gap: it emits the
artifacts, loads them in headless Chrome, and asserts on computed layout +
behavior — histogram bars have real height, a facet chip hides rows, the
histogram brush filters the timeline, and the process tree expands.

Dependency-light and CI-safe: uses ONLY a Chrome/Chromium binary via `--dump-dom`
(no Playwright, no extra pip/npm deps). If no browser is found it SKIPs cleanly
(exit 0) so a fresh clone without Chrome still passes the gate.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ATTACKFLOW_PARENT = REPO / "services" / "agent" / "findevil_agent"

CHROME_CANDIDATES = [
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
    "/opt/google/chrome/chrome",
]


def find_chrome() -> str | None:
    for c in CHROME_CANDIDATES:
        p = shutil.which(c) if "/" not in c else (c if Path(c).exists() else None)
        if p:
            return p
    return None


# A synthetic case (evidence-agnostic: generic host/T-codes/times) rich enough to
# exercise the histogram + facets + brush: several events across 3 days, mixed
# confidence tiers, mixed significance, one linked to a finding.
def _event(ts, conf, tech, sig, summary, linked=False):
    ev = {
        "timestamp_utc": ts,
        "confidence": conf,
        "attck_techniques": [tech],
        "significance": sig,
        "summary": summary,
        "entities": {"host": "HOST-X"},
        "source_record_ref": f"rec:{tech}",
    }
    if linked:
        ev["linked_finding_ids"] = ["f-1"]
        ev["entities"]["pid"] = 1200  # cross-links the finding to evil.exe -> flagged
    return ev


SYNTH_VERDICT = {
    "case_id": "render-smoke",
    "attack_story": {"headline": "Render smoke synthetic case"},
    "verdict": "SUSPICIOUS",
    "findings": [
        {
            "finding_id": "f-1",
            "mitre_technique": "T1070.001",
            "named_technique": "Log clearing (T1070.001)",
            "description": "d",
            "host": "HOST-X",
            "ts": "2021-03-01T00:00:00Z",
            "confidence": "CONFIRMED",
            "tool_call_id": "tc-1",
        },
        {
            "finding_id": "f-2",
            "mitre_technique": "T1547.001",
            "named_technique": "Run key (T1547.001)",
            "description": "d",
            "host": "HOST-X",
            "ts": "2021-06-15T00:00:00Z",
            "confidence": "INFERRED",
            "tool_call_id": "tc-2",
        },
        {
            "finding_id": "f-3",
            "mitre_technique": "T1083",
            "named_technique": "File discovery (T1083)",
            "description": "d",
            "host": "HOST-X",
            "ts": "2021-09-20T00:00:00Z",
            "confidence": "HYPOTHESIS",
            "tool_call_id": "tc-3",
        },
    ],
    "normalized_timeline": {
        "events": [
            _event("2021-03-01T09:00:00Z", "HYPOTHESIS", "T1083", "context", "ctx a"),
            _event("2021-03-01T09:05:00Z", "HYPOTHESIS", "T1083", "context", "ctx b"),
            _event("2021-03-01T09:10:00Z", "INFERRED", "T1547.001", "context", "ctx c"),
            _event(
                "2021-06-15T12:00:00Z",
                "INFERRED",
                "T1547.001",
                "finding_support",
                "mid a",
            ),
            _event(
                "2021-06-15T12:30:00Z",
                "CONFIRMED",
                "T1070.001",
                "finding_support",
                "hit",
                linked=True,
            ),
            _event(
                "2021-06-15T13:00:00Z",
                "CONFIRMED",
                "T1070.001",
                "finding_support",
                "hit2",
                linked=True,
            ),
            _event("2021-09-20T18:00:00Z", "HYPOTHESIS", "T1055", "context", "late a"),
            _event("2021-09-20T18:45:00Z", "HYPOTHESIS", "T1055", "context", "late b"),
        ]
    },
    "indicators": {"hosts": ["HOST-X"]},
    "entity_index": {"hosts": [{"value": "HOST-X"}]},
    "attack_coverage": {"observed_techniques": ["T1070.001"]},
}

# A small process table (one pid linked so it renders flagged) for the tree view.
SYNTH_PSSCAN = [
    {
        "pid": 4,
        "ppid": 0,
        "image_name": "System",
        "create_time_iso": "2021-06-15T00:00:00Z",
    },
    {
        "pid": 400,
        "ppid": 4,
        "image_name": "services.exe",
        "create_time_iso": "2021-06-15T00:00:01Z",
    },
    {
        "pid": 1200,
        "ppid": 400,
        "image_name": "evil.exe",
        "create_time_iso": "2021-06-15T12:30:00Z",
    },
]

# In-page assertions appended to timeline.html, result written to <title>.
HARNESS = r"""
<script>
(function () {
  // unfiltered count (by .tl-hidden CLASS — reflects facet/brush filters across
  // every day, open or collapsed).
  function kept(){return document.querySelectorAll('.tl-row:not(.tl-hidden)').length;}
  // on-screen count (offsetParent — reflects actual layout/render + collapse).
  function onscreen(){return [].slice.call(document.querySelectorAll('.tl-row')).filter(function(e){return e.offsetParent!==null;}).length;}
  function fail(m){document.title='RENDERSMOKE:FAIL '+m;}
  try {
    // 1) histogram bars exist and have real height (invisible-render guard)
    var bars=[].slice.call(document.querySelectorAll('.tl-hist rect')).filter(function(r){return r.getAttribute('data-b')!==null;});
    if(!bars.length){return fail('no histogram bars');}
    if(!bars.some(function(r){return parseFloat(r.getAttribute('height')||0)>0.5;})){return fail('all histogram bars zero-height');}
    // 2) rows actually render on screen (the open day's rows must be laid out)
    var total=document.querySelectorAll('.tl-row').length;
    if(total===0){return fail('no rows');}
    if(onscreen()===0){return fail('no rows visible on screen (open day not rendered)');}
    var k0=kept();
    // 3) facet: toggle 'context' OFF -> fewer kept rows
    var chip=document.querySelector('.tl-chip[data-val="context"]');
    if(!chip){return fail('no context chip');}
    chip.click();
    var k1=kept();
    if(!(k1<k0)){return fail('facet did not reduce kept rows '+k0+'->'+k1);}
    chip.click(); // restore
    if(kept()!==k0){return fail('facet toggle not reversible '+k0+'->'+kept());}
    // 4) brush a window -> filters kept rows AND shows a date-range label.
    // The histogram SVG is width:100% of its container; in headless (no real
    // paint loop) that container is intermittently zero-width for the whole
    // virtual-time budget, and the brush handler maps clientX through
    // getBoundingClientRect().width — a zero width collapses the drag. Pin the
    // SVG to its own viewBox width so the client rect is deterministically real;
    // this only fixes the harness's measurement, not the interaction under test
    // (a real viewport never sizes the histogram at zero).
    var svg=document.querySelector('.tl-hist');
    if(!svg){return fail('no histogram svg');}
    var vb=(svg.getAttribute('viewBox')||'').split(/\s+/);
    var vbw=(vb.length===4?parseFloat(vb[2]):0)||900;
    svg.style.width=vbw+'px'; svg.style.maxWidth='none';
    var b=svg.getBoundingClientRect();  // getBoundingClientRect forces reflow
    if(!(b.width>10)){return fail('histogram not laid out even after pinning width ('+Math.round(b.width)+')');}
    var y=b.top+b.height*0.5;
    function m(t,x){var e=new MouseEvent(t,{bubbles:true,clientX:x,clientY:y}); (t==='mousedown'?svg:window).dispatchEvent(e);}
    m('mousedown', b.left+b.width*0.40); m('mousemove', b.left+b.width*0.62); m('mouseup', b.left+b.width*0.62);
    var k2=kept();
    var info=document.querySelector('[class*="brush-info"]');
    if(!(info && /\d{4}-\d{2}-\d{2}/.test(info.textContent||''))){return fail('brush produced no range label');}
    if(k2>=k0){return fail('brush did not reduce kept rows '+k0+'->'+k2);}
    document.title='RENDERSMOKE:OK bars='+bars.length+' rows='+total+' facet='+k0+'->'+k1+' brush='+k0+'->'+k2;
  } catch(err){ fail('exc '+(err&&err.message||err)); }
})();
</script>
"""


HARNESS_SUMMARY = r"""
<script>
(function () {
  function onscreen(sel){return [].slice.call(document.querySelectorAll(sel)).filter(function(e){return e.offsetParent!==null;}).length;}
  function fail(m){document.title='RENDERSMOKE:FAIL '+m;}
  try {
    var cards=document.querySelectorAll('.afs-card').length;
    if(!cards){return fail('no summary cards');}
    if(onscreen('.afs-card')===0){return fail('summary cards not rendered on screen');}
    if(!document.querySelector('.afs-card.afs-confirmed')){return fail('no confirmed card');}
    document.title='RENDERSMOKE:OK cards='+cards;
  } catch(err){ fail('exc '+(err&&err.message||err)); }
})();
</script>
"""

HARNESS_PTREE = r"""
<script>
(function () {
  function onscreen(sel){return [].slice.call(document.querySelectorAll(sel)).filter(function(e){return e.offsetParent!==null;}).length;}
  function fail(m){document.title='RENDERSMOKE:FAIL '+m;}
  try {
    if(!document.querySelector('.pt-tree')){return fail('no process tree');}
    var n0=onscreen('summary, .pt-leaf');
    if(n0===0){return fail('process tree not rendered on screen');}
    if(!document.querySelector('.pt-tag')){return fail('no flagged-process tag');}
    var ex=document.querySelector('.pt-expand-all'); if(!ex){return fail('no expand-all button');}
    ex.click();
    var n1=onscreen('summary, .pt-leaf');
    if(!(n1>=n0)){return fail('expand-all reduced visible nodes '+n0+'->'+n1);}
    document.title='RENDERSMOKE:OK nodes='+n0+'->'+n1;
  } catch(err){ fail('exc '+(err&&err.message||err)); }
})();
</script>
"""


def _title_from_dom(dom: str) -> str:
    lo = dom.find("<title>")
    hi = dom.find("</title>", lo)
    return dom[lo + 7 : hi] if lo != -1 and hi != -1 else ""


def _drive(chrome: str, html_path: Path, label: str) -> bool:
    # A FRESH profile per launch. A shared/reused --user-data-dir races on
    # Chrome's SingletonLock across the sequential launches, and a launch that
    # loses the race dumps a DOM whose harness never ran ("no result title").
    # Keep it under a short base dir (~/.cache) so the control socket path stays
    # under the 108-char unix-socket limit.
    profile = Path(tempfile.mkdtemp(prefix="afrs-", dir=str(Path.home() / ".cache")))
    cmd = [
        chrome,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        # A definite viewport so the histogram SVG lays out with a real,
        # non-zero client width. Headless without this can size an inline SVG at
        # ~0 width, and the brush handler maps clientX through
        # getBoundingClientRect().width — a zero width collapses the drag and the
        # date-range label never appears (the root cause of a rare flake).
        "--window-size=1280,1024",
        "--virtual-time-budget=6000",
        f"--user-data-dir={profile}",
        "--dump-dom",
        f"file://{html_path}",
    ]
    # Chrome's control socket lives under TMPDIR; the project's contained TMPDIR is a
    # very deep path that overflows the 108-char unix-socket limit and silently kills
    # the launch. Point it (and the profile) at a short dir so headless Chrome starts.
    env = {**os.environ, "TMPDIR": str(Path.home() / ".cache")}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=env)
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"FAIL: chrome failed for {label}: {exc}")
        return False
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    title = _title_from_dom(r.stdout)
    if title.startswith("RENDERSMOKE:OK"):
        print(f"  {label}: {title}")
        return True
    print(f"FAIL: {label}: {title or '(no result title — page did not run)'}")
    return False


def main() -> int:
    chrome = find_chrome()
    if not chrome:
        print(
            "SKIP: no Chrome/Chromium found (render/interaction checks need a browser)"
        )
        return 0
    print(f"chrome: {chrome}")

    sys.path.insert(0, str(ATTACKFLOW_PARENT))
    from attackflow import emit  # top-level, host-py safe

    with tempfile.TemporaryDirectory() as td:
        case = Path(td) / "case"
        case.mkdir()
        (case / "verdict.json").write_text(json.dumps(SYNTH_VERDICT))
        (case / "psscan.json").write_text(json.dumps(SYNTH_PSSCAN))
        emit(case)
        af = case / "attack-flow"

        checks = [
            ("timeline.html", HARNESS, "timeline (histogram+facet+brush)"),
            ("attack-summary.html", HARNESS_SUMMARY, "summary (cards render)"),
            ("process-tree.html", HARNESS_PTREE, "process-tree (render+expand)"),
        ]
        ok = True
        for name, harness, label in checks:
            harness_path = case / f"{name}.harness.html"
            harness_path.write_text(
                (af / name).read_text(encoding="utf-8") + harness, encoding="utf-8"
            )
            ok = _drive(chrome, harness_path, label) and ok

    if ok:
        print("attack-flow render/interaction smoke: OK")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
