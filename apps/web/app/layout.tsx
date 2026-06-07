import type { Metadata } from "next";
import "./globals.css";

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
    <html lang="en">
      <head>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
      </head>
      <body>{children}</body>
    </html>
  );
}
