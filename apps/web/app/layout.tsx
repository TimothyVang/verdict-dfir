import type { Metadata } from "next";
import { JetBrains_Mono, Fraunces, Archivo } from "next/font/google";
import "./globals.css";
import CaseShell from "@/components/CaseShell";

// The editorial "forensic case file" type system (mirrors the demo video):
//   Fraunces (SERIF)  — display headlines / mastheads / panel titles
//   Archivo  (GROTESK) — kickers, labels, nav, furniture, section headings
//   JetBrains Mono     — all data: terminal rows, hashes, paths, timestamps
// next/font self-hosts each at build time (offline-safe) and exposes a CSS
// variable that lib/verdict-ui.tsx's MONO/SERIF/GROTESK tokens reference.
const jetBrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "700", "800"],
  variable: "--font-jbm",
  display: "swap",
});

const fraunces = Fraunces({
  subsets: ["latin"],
  weight: ["400", "600", "900"],
  style: ["normal", "italic"],
  variable: "--font-fraunces",
  display: "swap",
});

const archivo = Archivo({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-archivo",
  display: "swap",
});

export const metadata: Metadata = {
  title: "VERDICT — DFIR at machine speed.",
  description:
    "VERDICT is a DFIR investigation dashboard with a live, hash-chained audit stream — every tool call and finding rendered in real time from the tamper-evident JSONL chain of custody.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${jetBrainsMono.variable} ${fraunces.variable} ${archivo.variable}`}>
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
      </head>
      <body>
        <CaseShell>{children}</CaseShell>
      </body>
    </html>
  );
}
