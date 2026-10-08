import type { Stats } from "../types";
import { Hint } from "./common";

interface Card {
  label: string;
  value: number;
  hint: string;
  accent?: boolean;
}

export function Metrics({ stats }: { stats: Stats }) {
  const cards: Card[] = [
    {
      label: "Lookups checked",
      value: stats.lookups_checked,
      hint: "DNS lookups that were inspected. Known-safe domains are skipped.",
    },
    {
      label: "Warnings raised",
      value: stats.warnings,
      hint: "Each warning groups repeated matches for the same host, domain and type.",
      accent: true,
    },
    {
      label: "Total matches",
      value: stats.matches,
      hint: "How many individual lookups triggered a warning, before grouping.",
    },
    {
      label: "Hosts involved",
      value: stats.hosts,
      hint: "Distinct computers that raised at least one warning.",
    },
  ];

  return (
    <div className="metrics">
      {cards.map((c) => (
        <div key={c.label} className={`card metric${c.accent ? " accent" : ""}`}>
          <div className="label">
            {c.label}
            <Hint text={c.hint} />
          </div>
          <div className="value">{c.value.toLocaleString()}</div>
        </div>
      ))}
    </div>
  );
}
