// ReportPanel — the payoff. Once the run finalizes, surfaces the signed PDF
// report (view in-pane via same-origin iframe, download, share) plus the other
// downloadable case artifacts (verdict, manifest, timeline). When the report is
// gated for expert review (engine QA) it says so honestly and still offers the
// artifacts that exist.

"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { REPORT_ARTIFACT_LABELS } from "@/lib/report-artifacts";
import { MONO, RADIUS, SectionHeading, VERDICT } from "@/lib/verdict-ui";

interface ReportFile {
  name: string;
  available: boolean;
  bytes: number;
}

interface ReportPanelProps {
  caseDir: string;
  manifestDone: boolean;
  onReadyChange?: (ready: boolean) => void;
}

function reportHref(caseDir: string, file: string, dl = false): string {
  return `/api/report?case=${encodeURIComponent(caseDir)}&file=${encodeURIComponent(file)}${dl ? "&dl=1" : ""}`;
}

function btnStyle(accent: string): React.CSSProperties {
  return {
    background: `${accent}26`,
    border: `1px solid ${accent}`,
    color: accent,
    borderRadius: RADIUS.pill,
    padding: "6px 14px",
    fontFamily: MONO,
    fontWeight: 700,
    fontSize: 12,
    cursor: "pointer",
    textDecoration: "none",
    display: "inline-block",
  };
}

export function ReportPanel({ caseDir, manifestDone, onReadyChange }: ReportPanelProps) {
  const [files, setFiles] = useState<ReportFile[]>([]);
  const [showViewer, setShowViewer] = useState(false);
  const [shared, setShared] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const pdf =
    files.find((f) => f.name === "REPORT.pdf" && f.available) ??
    files.find((f) => f.name === "REPORT.new.pdf" && f.available);
  const pdfName = pdf?.name;
  const available = files.filter((f) => f.available);

  useEffect(() => {
    onReadyChange?.(Boolean(pdf));
  }, [pdf, onReadyChange]);

  const refresh = useCallback(async () => {
    if (!caseDir) return;
    try {
      const res = await fetch(`/api/report?case=${encodeURIComponent(caseDir)}&list=1`);
      if (!res.ok) return;
      const data = (await res.json()) as { files: ReportFile[] };
      setFiles(data.files ?? []);
    } catch {
      // best-effort
    }
  }, [caseDir]);

  // Fetch on connect; poll for the PDF while the run is finalizing.
  useEffect(() => {
    if (!caseDir) {
      setFiles([]);
      return;
    }
    void refresh();
    if (manifestDone) {
      let ticks = 0;
      pollRef.current = setInterval(() => {
        ticks += 1;
        void refresh();
        if (ticks > 20 && pollRef.current) clearInterval(pollRef.current);
      }, 2000);
    }
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [caseDir, manifestDone, refresh]);

  const onShare = useCallback(() => {
    if (!caseDir || !pdfName) return;
    const url = `${window.location.origin}${reportHref(caseDir, pdfName)}`;
    void navigator.clipboard?.writeText(url);
    setShared(true);
    setTimeout(() => setShared(false), 1600);
  }, [caseDir, pdfName]);

  return (
    <section
      aria-label="Report"
      style={{
        background: VERDICT.surface,
        border: `1px solid ${pdf ? VERDICT.accentPurple : VERDICT.border}`,
        borderRadius: RADIUS.card,
        padding: 18,
        transition: "border-color 300ms ease",
      }}
    >
      <SectionHeading>REPORT</SectionHeading>

      {!caseDir ? (
        <p style={{ fontFamily: MONO, fontSize: 13, color: VERDICT.mutedDark, margin: 0 }}>
          connect a case to view its signed report.
        </p>
      ) : pdf ? (
        <>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
            <button type="button" style={btnStyle(VERDICT.accentPurpleLight)} onClick={() => setShowViewer((v) => !v)}>
              {showViewer ? "Hide" : "View"}
            </button>
            <a style={btnStyle(VERDICT.confirmed)} href={reportHref(caseDir, pdfName ?? "REPORT.pdf", true)}>
              Download
            </a>
            <button type="button" style={btnStyle(VERDICT.muted)} onClick={onShare}>
              {shared ? "copied ✓" : "Share"}
            </button>
          </div>
          {showViewer ? (
            <iframe
              title={pdfName ?? "REPORT.pdf"}
              src={reportHref(caseDir, pdfName ?? "REPORT.pdf")}
              style={{ width: "100%", height: 520, border: `1px solid ${VERDICT.border}`, borderRadius: RADIUS.tile, background: "#fff" }}
            />
          ) : null}
        </>
      ) : (
        <p style={{ fontFamily: MONO, fontSize: 13, color: VERDICT.muted, margin: "0 0 12px" }}>
          {manifestDone
            ? "no PDF report — it is gated for expert review (engine QA) or still rendering. Artifacts below are available."
            : "the signed report appears here once the run finalizes."}
        </p>
      )}

      {available.length > 0 ? (
        <div style={{ marginTop: 8 }}>
          <div style={{ fontFamily: MONO, fontSize: 12, color: VERDICT.mutedDark, marginBottom: 6 }}>
            artifacts
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {available
              .filter((f) => f.name !== pdfName)
              .map((f) => (
                <a
                  key={f.name}
                  href={reportHref(caseDir, f.name, true)}
                  style={{
                    fontFamily: MONO,
                    fontSize: 11,
                    color: VERDICT.hypothesis,
                    border: `1px solid ${VERDICT.border}`,
                    borderRadius: RADIUS.pill,
                    padding: "4px 10px",
                    textDecoration: "none",
                  }}
                >
                  {REPORT_ARTIFACT_LABELS[f.name] ?? f.name} ↓
                </a>
              ))}
          </div>
        </div>
      ) : null}
    </section>
  );
}
