import type { Metadata } from "next";
import { JetBrains_Mono, Archivo, Archivo_Narrow, Inter, Caveat } from "next/font/google";
import "./globals.css";
import CaseShell from "@/components/CaseShell";

// VERDICT v2 type system, matching the brand board (VERDICT_DFIR_SVG_Assets_v2):
//   Inter          — body/UI copy, chips, controls (the clean-sans BODY role)
//   Archivo Narrow — heavy CONDENSED editorial headlines ("TRUTH IN THE TRACE.")
//   Archivo        — editorial furniture: kickers, labels, nav, section headings
//   JetBrains Mono — evidence/data ONLY: hashes, paths, timestamps, tool output
//   Caveat         — restrained handwritten annotations only
// next/font self-hosts each at build time and exposes the CSS variables the
// lib/verdict-ui.tsx tokens reference.
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

const archivoNarrow = Archivo_Narrow({
  subsets: ["latin"],
  weight: ["600", "700"],
  variable: "--font-anarrow",
  display: "swap",
});

const inter = Inter({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700", "800"],
  variable: "--font-inter",
  display: "swap",
});

const caveat = Caveat({
  subsets: ["latin"],
  weight: ["400", "700"],
  variable: "--font-caveat",
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
    <html
      lang="en"
      className={`${jetBrainsMono.variable} ${archivo.variable} ${archivoNarrow.variable} ${inter.variable} ${caveat.variable}`}
    >
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
      </head>
      <body>
        <CaseShell>{children}</CaseShell>
      </body>
    </html>
  );
}
