import { useMemo, useState } from "react";
import type { Severity, Warning } from "../types";
import { SeverityBadge } from "./common";

const SEVERITIES: Severity[] = ["High", "Medium", "Low"];

function fmtTime(epoch: number): string {
  const d = new Date(epoch * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function WarningsTable({ warnings }: { warnings: Warning[] }) {
  const categories = useMemo(
    () => [...new Set(warnings.map((w) => w.attack_type))].sort(),
    [warnings],
  );
  const [activeCats, setActiveCats] = useState<Set<string>>(() => new Set(categories));
  const [activeSevs, setActiveSevs] = useState<Set<string>>(() => new Set(SEVERITIES));

  const toggle = (set: Set<string>, value: string, update: (s: Set<string>) => void) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    update(next);
  };

  const rows = useMemo(
    () =>
      warnings
        .filter((w) => activeCats.has(w.attack_type) && activeSevs.has(w.severity))
        .sort((a, b) => a.timestamp - b.timestamp),
    [warnings, activeCats, activeSevs],
  );

  return (
    <>
      <div className="filters" role="group" aria-label="Filter by category">
        {categories.map((c) => (
          <button
            key={c}
            className={`chip${activeCats.has(c) ? " on" : ""}`}
            aria-pressed={activeCats.has(c)}
            onClick={() => toggle(activeCats, c, setActiveCats)}
          >
            {c}
          </button>
        ))}
      </div>
      <div className="filters" role="group" aria-label="Filter by severity">
        {SEVERITIES.filter((s) => warnings.some((w) => w.severity === s)).map((s) => (
          <button
            key={s}
            className={`chip${activeSevs.has(s) ? " on" : ""}`}
            aria-pressed={activeSevs.has(s)}
            onClick={() => toggle(activeSevs, s, setActiveSevs)}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Severity</th>
              <th>Category</th>
              <th>Host</th>
              <th>Domain</th>
              <th>Matches</th>
              <th>What this means</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((w, i) => (
              <tr key={`${w.src_ip}-${w.attack_type}-${i}`}>
                <td className="mono">{fmtTime(w.timestamp)}</td>
                <td><SeverityBadge severity={w.severity} /></td>
                <td>{w.attack_type}</td>
                <td className="mono host">{w.src_ip}</td>
                <td className="mono">{w.domain}</td>
                <td>{w.hit_count.toLocaleString()}</td>
                <td className="reason">{w.reason}</td>
              </tr>
            ))}
            {!rows.length && (
              <tr>
                <td colSpan={7} className="empty">No warnings match the current filters.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
