import { useMemo } from "react";
import type { Warning } from "../types";

export function TopHosts({ warnings }: { warnings: Warning[] }) {
  const rows = useMemo(() => {
    const map = new Map<string, { warnings: number; matches: number; cats: Set<string> }>();
    for (const w of warnings) {
      const e = map.get(w.src_ip) ?? { warnings: 0, matches: 0, cats: new Set() };
      e.warnings += 1;
      e.matches += w.hit_count;
      e.cats.add(w.attack_type);
      map.set(w.src_ip, e);
    }
    return [...map.entries()]
      .map(([host, e]) => ({
        host,
        warnings: e.warnings,
        matches: e.matches,
        categories: [...e.cats].sort().join(", "),
      }))
      .sort((a, b) => b.warnings - a.warnings)
      .slice(0, 10);
  }, [warnings]);

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>Warnings</th>
            <th>Matches</th>
            <th>Categories</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.host}>
              <td className="mono">{r.host}</td>
              <td>{r.warnings}</td>
              <td>{r.matches.toLocaleString()}</td>
              <td className="muted">{r.categories}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
