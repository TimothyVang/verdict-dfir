export interface Beat {
  number: number;
  title: string;
  startS: number;
  endS: number;
  rubric: string;
  narration: string;
  accentColor: string;
}

// 10 beats — newcomer-first product walkthrough.
// Narration is the canonical voiceover source (read by make-demo-video-tts.py).
// startS/endS are re-timed to each beat's measured audio + a short breath
// (hybrid pacing — no dead air). Durations below are in sync with the generated
// public/audio/beat_NN.mp3 files (measured 2026-06-07).
export const BEATS: Beat[] = [
  {
    number: 1,
    title: "What VERDICT is",
    startS: 0,
    endS: 27,
    rubric: "Cold open",
    accentColor: "#9b59b6",
    narration:
      "Every security team has the same nightmare: someone breaks into a computer, and now you have to figure out exactly what they did, fast. That work is called digital forensics, and by hand it can take days. VERDICT does it in minutes. It's an AI agent that takes the evidence from a compromised machine, investigates it for you, and signs its conclusions, so you don't just get answers, you get answers you can prove.",
  },
  {
    number: 2,
    title: "It starts in Claude Code",
    startS: 27,
    endS: 49,
    rubric: "How to run it",
    accentColor: "#6f93b8",
    narration:
      "And it's surprisingly simple to run. VERDICT lives inside Claude Code, the A.I. assistant in your terminal. You open Claude Code and type one line: investigate, followed by the evidence, a hard-drive image, or a snapshot of a computer's memory. That's the whole command. From there the agent takes over and does the rest while you watch.",
  },
  {
    number: 3,
    title: "How the case progresses",
    startS: 49,
    endS: 80,
    rubric: "How it works",
    accentColor: "#7fae6e",
    narration:
      "So what's it actually doing? First it makes a locked, read-only copy of the evidence, so the original is never touched, which matters if this ends up in court. Then it splits into two separate teams of agents that investigate from opposite angles. Each runs real forensic tools and writes up what it finds. Wherever the two disagree, that conflict is flagged out loud, not swept away. Finally, every finding is double-checked against the raw tool output before it makes the report.",
  },
  {
    number: 4,
    title: "The toolbox",
    startS: 80,
    endS: 105,
    rubric: "The tools",
    accentColor: "#c79a4a",
    narration:
      "The agent isn't guessing. It runs thirty-one real forensic tools, the same kind professionals use. And by design, not one of them can run arbitrary commands on your system, so it can't be tricked into going rogue. Each tool answers one plain question: What programs ran on this machine? What did the system quietly log? What left over the network? And, can we prove it?",
  },
  {
    number: 5,
    title: "Two investigators",
    startS: 105,
    endS: 132,
    rubric: "Competing hypotheses",
    accentColor: "#d6452f",
    narration:
      "Those two teams are the clever part. One assumes the attacker broke in to stay and dig in. The other assumes they came to steal data and leave. Same evidence, opposite theories. A single analyst tends to lock onto their first guess. VERDICT forces both sides to argue on the record, shows you where they disagree, and only then decides. You see the reasoning, not just a conclusion handed down.",
  },
  {
    number: 6,
    title: "Watch it live",
    startS: 132,
    endS: 158,
    rubric: "The dashboard",
    accentColor: "#9b59b6",
    narration:
      "And while it runs, you're not staring at a blank screen. This is the live dashboard. Each finding appears the moment it's proven, tagged confirmed, inferred, or hypothesis, so you always know how sure the agent is. A timeline builds itself, the pipeline lights up stage by stage, and every finding links straight back to the exact tool call behind it. Nothing hidden, nothing hand-waved.",
  },
  {
    number: 7,
    title: "Proof you can take to court",
    startS: 158,
    endS: 184,
    rubric: "Chain of custody",
    accentColor: "#6f93b8",
    narration:
      "Here's what really sets it apart. Every action is locked into a tamper-proof chain. Change one link, and the whole thing breaks. At the end, that chain is sealed with a cryptographic signature, logged publicly. So years later anyone, a colleague, an auditor, a court, can verify the entire investigation offline, without ever trusting us. It's evidence that proves its own honesty.",
  },
  {
    number: 8,
    title: "Then it acts",
    startS: 184,
    endS: 206,
    rubric: "Automation",
    accentColor: "#7fae6e",
    narration:
      "And the second the verdict is signed, VERDICT acts. This is the automation layer, built on a tool called n8n. Wire it to do whatever your team needs: fire a Slack alert, open a ticket automatically, push a dangerous indicator out to your other defenses. The investigation finishes, and the response kicks off on its own.",
  },
  {
    number: 9,
    title: "From one host to the fleet",
    startS: 206,
    endS: 225,
    rubric: "Scale",
    accentColor: "#c79a4a",
    narration:
      "One computer is just the demo. A real breach touches dozens of machines. VERDICT scales right up. It investigates twenty-two hosts from a single command, saves its place as it goes so a crash costs nothing, and spots patterns across machines that no single look could catch.",
  },
  {
    number: 10,
    title: "Get the receipts",
    startS: 225,
    endS: 239,
    rubric: "Signed verdict",
    accentColor: "#9b59b6",
    narration:
      "And at the end you get the one thing that matters: a signed verdict you can stand behind. VERDICT is open source, free, and ready today. Point it at your evidence, and get the truth, with the receipts.",
  },
];

export const FPS = 30;
export const WIDTH = 1920;
export const HEIGHT = 1080;
// Total runtime is the last beat's end — keeps Root.tsx in sync after re-timing.
export const TOTAL_FRAMES = BEATS[BEATS.length - 1].endS * FPS;
