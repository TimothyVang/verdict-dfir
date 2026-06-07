"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";

import {
  buildCodexAppDeeplink,
  buildCodexInvestigationPrompt,
  CODEX_MODE_LABELS,
  CODEX_PRESETS,
  type CodexMode,
} from "@/lib/codex-presets";
import { DashboardNav } from "@/components/DashboardNav";

type ChatRole = "operator" | "codex" | "system";

interface ChatMessage {
  id: string;
  role: ChatRole;
  content: string;
}

interface CodexStatus {
  enabled: boolean;
  repoRoot: string;
  rustMcpBinaryBuilt: boolean;
  readinessSummary: CodexReadinessSummary | null;
  note: string;
}

interface CodexReadinessSummary {
  summaryPath: string;
  generatedAt?: string;
  runId?: string;
  mode?: string;
  readinessState?: string;
  packetZip?: string | null;
  packetDir?: string | null;
  packetManifest?: string | null;
  evidenceRunDir?: string | null;
  customerReleasable?: boolean;
  blockers: string[];
  warnings: string[];
  reportLinks: Array<{
    label: string;
    path: string;
    href: string;
  }>;
}

const INITIAL_MESSAGE: ChatMessage = {
  id: "intro",
  role: "system",
  content:
    "This is a Find Evil operator wrapper for Codex. It cannot send text into an already-running Codex CLI TUI because the TUI does not expose an input API. Use Copy TUI prompt for the terminal, Open Codex app for a deeplink, or Run in chat for a separate one-shot codex exec run.",
};

export default function CodexPage() {
  const [mode, setMode] = useState<CodexMode>("evtx");
  const [evidencePath, setEvidencePath] = useState("fixtures/single-evtx/Security.evtx");
  const [prompt, setPrompt] = useState(CODEX_PRESETS[0]?.prompt ?? "");
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_MESSAGE]);
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState<CodexStatus | null>(null);

  useEffect(() => {
    fetch("/api/codex", { cache: "no-store" })
      .then((res) => res.json() as Promise<CodexStatus>)
      .then(setStatus)
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : String(err);
        setMessages((prev) => [
          ...prev,
          {
            id: crypto.randomUUID(),
            role: "system",
            content: `Unable to read Codex route status: ${msg}`,
          },
        ]);
      });
  }, []);

  const generatedPrompt = useMemo(
    () =>
      buildCodexInvestigationPrompt({
        mode,
        message: prompt,
        evidencePath,
      }),
    [evidencePath, mode, prompt],
  );

  const codexAppHref = useMemo(
    () =>
      buildCodexAppDeeplink({
        prompt: generatedPrompt,
        repoRoot: status?.repoRoot,
      }),
    [generatedPrompt, status?.repoRoot],
  );

  const applyPreset = (presetId: string): void => {
    const preset = CODEX_PRESETS.find((candidate) => candidate.id === presetId);
    if (!preset) return;
    setMode(preset.mode);
    setPrompt(preset.prompt);
    if (preset.placeholderEvidence) setEvidencePath(preset.placeholderEvidence);
  };

  const runCodex = async (): Promise<void> => {
    if (running || prompt.trim().length === 0) return;

    const operatorMessage: ChatMessage = {
      id: crypto.randomUUID(),
      role: "operator",
      content: prompt.trim(),
    };
    const codexMessageId = crypto.randomUUID();
    setMessages((prev) => [
      ...prev,
      operatorMessage,
      { id: codexMessageId, role: "codex", content: "" },
    ]);
    setRunning(true);

    try {
      const res = await fetch("/api/codex", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode, evidencePath, message: prompt }),
      });

      if (!res.ok || !res.body) {
        const text = await res.text();
        updateMessage(codexMessageId, text || `Codex route failed with ${res.status}`);
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let accumulated = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        accumulated += decoder.decode(value, { stream: true });
        updateMessage(codexMessageId, accumulated);
      }
      accumulated += decoder.decode();
      updateMessage(codexMessageId, accumulated);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      updateMessage(codexMessageId, `Codex request failed: ${msg}`);
    } finally {
      setRunning(false);
    }
  };

  const updateMessage = (id: string, content: string): void => {
    setMessages((prev) =>
      prev.map((message) => (message.id === id ? { ...message, content } : message)),
    );
  };

  return (
    <main className="min-h-screen overflow-x-hidden px-4 py-6 text-ink md:px-8">
      <DashboardNav active="codex" variant="dark" />
      <div className="mx-auto max-w-7xl">
        <header className="grid gap-4 rounded-xl border border-hairline bg-surface p-6 md:grid-cols-[1.3fr_0.7fr]">
          <div>
            <p className="font-grotesk text-xs uppercase tracking-wide text-accent">Find Evil Codex UI</p>
            <h1 className="mt-3 font-serif text-3xl font-black tracking-tight md:text-5xl">
              Codex investigation cockpit
            </h1>
            <p className="mt-4 max-w-3xl text-sm leading-6 text-ink-muted md:text-base">
              A local wrapper for curated Codex prompts. Use the regular Codex TUI when you want its built-in dashboard; use this page when you want repeatable Find Evil investigation prompts, evidence-path guardrails, and a browser chat transcript.
            </p>
          </div>
          <div className="rounded-lg border border-hairline bg-surface p-4 text-sm">
            <p className="font-grotesk uppercase tracking-wide text-accent">Runner status</p>
            <p className="mt-3">
              API: {status?.enabled ? "enabled" : "disabled"}
            </p>
            <p>Rust MCP binary: {status?.rustMcpBinaryBuilt ? "built" : "missing"}</p>
            <p className="mt-3 text-xs text-ink-muted">
              Enable one-shot runs with <code className="font-mono">FINDEVIL_CODEX_UI_ENABLE=1</code>. Without it, this page still works as a prompt launcher.
            </p>
          </div>
        </header>

        <div className="mt-6 grid gap-6 lg:grid-cols-[360px_1fr]">
          <aside className="space-y-4">
            <section className="rounded-xl border border-confirmed/30 bg-surface p-4 text-sm text-ink">
              <h2 className="font-grotesk uppercase tracking-wide text-confirmed">Readiness summary</h2>
              {status?.readinessSummary ? (
                <div className="mt-3 space-y-3 text-xs leading-5">
                  <div>
                    <p>
                      State: <span className="font-bold">{status.readinessSummary.readinessState ?? "unknown"}</span>
                    </p>
                    {status.readinessSummary.generatedAt ? (
                      <p className="text-ink-muted">Generated: {status.readinessSummary.generatedAt}</p>
                    ) : null}
                  </div>
                  <div className="space-y-1 text-ink-muted">
                    <p className="break-words">Summary: {status.readinessSummary.summaryPath}</p>
                    {status.readinessSummary.packetZip ? (
                      <p className="break-words">Packet ZIP: {status.readinessSummary.packetZip}</p>
                    ) : null}
                  </div>
                  {status.readinessSummary.blockers.length > 0 ? (
                    <div>
                      <p className="font-grotesk uppercase tracking-wide text-alert">Blockers</p>
                      <ul className="mt-1 list-disc space-y-1 pl-4 text-alert">
                        {status.readinessSummary.blockers.map((blocker) => (
                          <li key={blocker}>{blocker}</li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <p className="text-confirmed">No blockers recorded in the latest local summary.</p>
                  )}
                  {status.readinessSummary.warnings.length > 0 ? (
                    <div>
                      <p className="font-grotesk uppercase tracking-wide text-inferred">Warnings</p>
                      <ul className="mt-1 list-disc space-y-1 pl-4 text-inferred">
                        {status.readinessSummary.warnings.map((warning) => (
                          <li key={warning}>{warning}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                  {status.readinessSummary.reportLinks.length > 0 ? (
                    <div>
                      <p className="font-grotesk uppercase tracking-wide text-confirmed">Reports</p>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {status.readinessSummary.reportLinks.map((report) => (
                          <a
                            key={report.path}
                            href={report.href}
                            className="rounded-lg border border-confirmed/40 px-2 py-1 font-bold text-confirmed transition hover:border-confirmed"
                          >
                            {report.label}
                          </a>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              ) : (
                <p className="mt-2 text-xs leading-5 text-ink-muted">
                  No local readiness summary found under <code className="font-mono">tmp/readiness-gates</code>. Run the readiness gate to populate packet state, blockers, warnings, and report paths here.
                </p>
              )}
            </section>

            <section className="rounded-xl border border-hairline bg-surface p-4">
              <h2 className="font-grotesk text-lg uppercase tracking-wide text-accent">Suggested investigations</h2>
              <div className="mt-4 space-y-3">
                {CODEX_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => applyPreset(preset.id)}
                    className="w-full rounded-lg border border-hairline bg-surface p-3 text-left transition hover:border-accent/30"
                  >
                    <span className="block text-sm font-bold text-ink">{preset.title}</span>
                    <span className="mt-1 block text-xs text-ink-muted">{preset.summary}</span>
                    <span className="mt-2 inline-block rounded-full bg-accent/20 px-2 py-1 font-grotesk text-[11px] uppercase tracking-wide text-accent">
                      {CODEX_MODE_LABELS[preset.mode]}
                    </span>
                  </button>
                ))}
              </div>
            </section>

            <section className="rounded-xl border border-inferred/30 bg-surface p-4 text-sm text-ink">
              <h2 className="font-grotesk uppercase tracking-wide text-inferred">Safety envelope</h2>
              <p className="mt-2 text-xs leading-5 text-ink-muted">
                The server runner is disabled by default. When enabled, it uses an ephemeral Codex exec command, disables the shell tool, and allowlists only the MCP tools required by the selected mode.
              </p>
            </section>

            <section className="rounded-xl border border-accent/30 bg-surface p-4 text-sm text-ink">
              <h2 className="font-grotesk uppercase tracking-wide text-accent">TUI boundary</h2>
              <p className="mt-2 text-xs leading-5 text-ink-muted">
                This browser page cannot type into a live Codex CLI TUI. Use Copy TUI prompt and paste it into the terminal, or use the Codex app deeplink when the desktop app is installed.
              </p>
            </section>
          </aside>

          <section className="rounded-xl border border-hairline bg-surface p-4">
            <div className="grid gap-4 md:grid-cols-[220px_1fr]">
              <label className="block text-sm">
                <span className="font-grotesk uppercase tracking-wide text-ink-muted">Mode</span>
                <select
                  value={mode}
                  onChange={(event) => setMode(event.target.value as CodexMode)}
                  className="mt-2 w-full rounded-lg border border-hairline bg-surface px-3 py-2 text-ink"
                >
                  {Object.entries(CODEX_MODE_LABELS).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block text-sm">
                <span className="font-grotesk uppercase tracking-wide text-ink-muted">Evidence or run path</span>
                <input
                  value={evidencePath}
                  onChange={(event) => setEvidencePath(event.target.value)}
                  className="mt-2 w-full rounded-lg border border-hairline bg-surface px-3 py-2 font-mono text-ink"
                  placeholder="fixtures/single-evtx/Security.evtx"
                />
              </label>
            </div>

            <div className="mt-4 h-[420px] overflow-y-auto rounded-xl border border-hairline bg-paper p-4">
              <div className="space-y-4">
                {messages.map((message) => (
                  <article
                    key={message.id}
                    className={
                      message.role === "operator"
                        ? "ml-auto max-w-[88%] rounded-xl bg-accent/20 p-4 text-ink"
                        : message.role === "codex"
                          ? "max-w-[88%] rounded-xl border border-hairline bg-surface p-4 text-ink"
                          : "max-w-[95%] rounded-xl border border-hairline bg-surface p-4 text-ink-muted"
                    }
                  >
                    <p className="mb-2 font-grotesk text-xs uppercase tracking-wide text-ink-muted">
                      {message.role}
                    </p>
                    <pre className="whitespace-pre-wrap break-words font-mono text-sm leading-6">
                      {message.content || (running ? "Codex is thinking..." : "")}
                    </pre>
                  </article>
                ))}
              </div>
            </div>

            <label className="mt-4 block text-sm">
              <span className="font-grotesk uppercase tracking-wide text-ink-muted">Prompt</span>
              <textarea
                value={prompt}
                onChange={(event) => setPrompt(event.target.value)}
                className="mt-2 min-h-32 w-full rounded-xl border border-hairline bg-surface px-3 py-2 font-mono text-ink"
              />
            </label>

            <div className="mt-4 flex flex-wrap gap-3">
              <button
                type="button"
                onClick={() => void runCodex()}
                disabled={running}
                className="rounded-xl bg-accent px-5 py-3 font-grotesk uppercase tracking-wide text-paper transition hover:bg-accent/80 disabled:cursor-not-allowed disabled:bg-ink-faint"
              >
                {running ? "Running Codex" : "Run in chat"}
              </button>
              <button
                type="button"
                onClick={() => navigator.clipboard.writeText(generatedPrompt)}
                className="rounded-xl border border-hairline px-5 py-3 font-grotesk uppercase tracking-wide text-ink-muted transition hover:border-accent/30 hover:text-ink"
              >
                Copy TUI prompt
              </button>
              <a
                href={codexAppHref}
                className="rounded-xl border border-hairline px-5 py-3 font-grotesk uppercase tracking-wide text-ink-muted transition hover:border-accent/30 hover:text-ink"
              >
                Open Codex app
              </a>
              <Link
                href="/"
                className="rounded-xl border border-hairline px-5 py-3 font-grotesk uppercase tracking-wide text-ink-muted transition hover:border-accent/30 hover:text-ink"
              >
                Audit dashboard
              </Link>
              <Link
                href="/debug"
                className="rounded-xl border border-hairline px-5 py-3 font-grotesk uppercase tracking-wide text-ink-muted transition hover:border-accent/30 hover:text-ink"
              >
                Debug stream
              </Link>
            </div>

            <details className="mt-4 rounded-xl border border-hairline bg-surface p-4 text-sm">
              <summary className="cursor-pointer font-grotesk uppercase tracking-wide text-accent">Generated guarded prompt</summary>
              <pre className="mt-3 max-h-64 overflow-y-auto whitespace-pre-wrap break-words font-mono text-xs leading-5 text-ink-muted">
                {generatedPrompt}
              </pre>
            </details>
          </section>
        </div>
      </div>
    </main>
  );
}
