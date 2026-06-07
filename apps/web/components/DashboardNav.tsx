// /debug stays reachable by URL (raw dev viewer) but is off the investigator nav.
const DASHBOARD_LINKS = [
  { href: "/", label: "Audit" },
  { href: "/setup", label: "Setup" },
];

interface DashboardNavProps {
  active: "audit" | "debug" | "setup";
  variant?: "light" | "dark";
}

export function DashboardNav({ active, variant = "light" }: DashboardNavProps) {
  // Both variants render the single editorial style; prop kept for caller compatibility.
  void variant;
  return (
    <nav
      aria-label="Dashboard views"
      className="mx-auto mb-6 flex max-w-7xl flex-wrap items-center gap-3 rounded-xl border border-hairline bg-surface p-3 text-sm text-ink-muted"
    >
      <span className="font-grotesk uppercase tracking-wide text-ink-muted">
        Dashboards
      </span>
      <div className="flex flex-wrap gap-2">
        {DASHBOARD_LINKS.map((link) => {
          const isActive = link.href === `/${active === "audit" ? "" : active}`;
          return (
            <a
              key={link.href}
              href={link.href}
              aria-current={isActive ? "page" : undefined}
              className={`rounded-lg px-3 py-2 font-grotesk uppercase tracking-wide transition ${
                isActive
                  ? "bg-accent text-paper"
                  : "border border-hairline text-ink-muted hover:border-accent/30 hover:text-ink"
              }`}
            >
              {link.label}
            </a>
          );
        })}
      </div>
    </nav>
  );
}
