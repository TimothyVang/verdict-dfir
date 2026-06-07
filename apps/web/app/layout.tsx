import type { Metadata } from "next";
import { JetBrains_Mono } from "next/font/google";
import "./globals.css";

// JetBrains Mono — the VERDICT typeface (matches the demo video). next/font
// self-hosts the files at build time (no runtime remote request, offline-safe)
// and exposes it as the --font-jbm CSS variable, which lib/verdict-ui.tsx's
// MONO token references. /codex + /debug keep their globals.css body font.
const jetBrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "700", "800"],
  variable: "--font-jbm",
  display: "swap",
});

export const metadata: Metadata = {
  title: "VERDICT — DFIR at machine speed.",
  description:
    "VERDICT by Find Evil! — SANS Hackathon 2026. Live audit dashboard tailing the hash-chained JSONL. Pool A / Pool B / verifier / judge / correlator role sprites. Amendment A3.",
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
    <html lang="en" className={jetBrainsMono.variable}>
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
      </head>
      <body>{children}</body>
    </html>
  );
}
