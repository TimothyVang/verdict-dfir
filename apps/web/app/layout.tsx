import type { Metadata } from "next";
import { JetBrains_Mono, Archivo } from "next/font/google";
import "./globals.css";
import CaseShell from "@/components/CaseShell";

// VERDICT v2 type system, matching the brand board:
//   Archivo        — heavy editorial headlines, labels, nav, furniture
//   JetBrains Mono — data: terminal rows, hashes, paths, timestamps
// next/font self-hosts each at build time and exposes variables referenced by
// lib/verdict-ui.tsx's legacy MONO/SERIF/GROTESK token names.
const jetBrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "700", "800"],
  variable: "--font-jbm",
  display: "swap",
});

const archivo = Archivo({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700", "800", "900"],
  variable: "--font-archivo",
  display: "swap",
});

export const metadata: Metadata = {
  title: "VERDICT — Show Me the Evidence",
  description:
    "VERDICT is a DFIR investigation dashboard with a live, hash-chained audit stream, reproducible findings, and evidence-first case review.",
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
    <html lang="en" className={`${jetBrainsMono.variable} ${archivo.variable}`}>
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
      </head>
      <body>
        <CaseShell>{children}</CaseShell>
      </body>
    </html>
  );
}
