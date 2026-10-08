import { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Legend,
} from "recharts";
import type { EntropyHistogram, Warning } from "../types";

type Colors = {
  series: string[];
  flagged: string;
  normal: string;
  grid: string;
  text: string;
  primary: string;
};

const axisStyle = (c: Colors) => ({ fill: c.text, fontSize: 12 });

const tooltipStyle = {
  background: "var(--surface)",
  border: "1px solid var(--border)",
  borderRadius: 10,
  color: "var(--text)",
  fontSize: 13,
  boxShadow: "var(--shadow)",
};

/** Warnings grouped by category (horizontal bars). */
export function CategoryBar({ warnings, colors }: { warnings: Warning[]; colors: Colors }) {
  const data = useMemo(() => {
    const counts = new Map<string, number>();
    for (const w of warnings) counts.set(w.attack_type, (counts.get(w.attack_type) ?? 0) + 1);
    return [...counts.entries()]
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => a.count - b.count);
  }, [warnings]);

  return (
    <div className="chart-box">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
          <CartesianGrid horizontal={false} stroke={colors.grid} />
          <XAxis type="number" allowDecimals={false} tick={axisStyle(colors)} stroke={colors.grid} />
          <YAxis
            type="category"
            dataKey="category"
            width={168}
            tick={axisStyle(colors)}
            stroke={colors.grid}
          />
          <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-2)" }} />
          <Bar dataKey="count" radius={[0, 6, 6, 0]} name="warnings">
            {data.map((_, i) => (
              <Cell key={i} fill={colors.series[i % colors.series.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Running total of warnings over the capture timeline. */
export function Timeline({ warnings, colors }: { warnings: Warning[]; colors: Colors }) {
  const data = useMemo(() => {
    const sorted = [...warnings].sort((a, b) => a.timestamp - b.timestamp);
    const t0 = sorted.length ? sorted[0].timestamp : 0;
    return sorted.map((w, i) => ({
      t: +(w.timestamp - t0).toFixed(1),
      total: i + 1,
      category: w.attack_type,
    }));
  }, [warnings]);

  return (
    <div className="chart-box">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ left: 0, right: 16, top: 8, bottom: 4 }}>
          <CartesianGrid stroke={colors.grid} />
          <XAxis
            dataKey="t"
            tick={axisStyle(colors)}
            stroke={colors.grid}
            label={{ value: "seconds", position: "insideBottom", offset: -2, fill: colors.text, fontSize: 11 }}
          />
          <YAxis allowDecimals={false} tick={axisStyle(colors)} stroke={colors.grid} />
          <Tooltip contentStyle={tooltipStyle} />
          <Line
            type="monotone"
            dataKey="total"
            name="warnings so far"
            stroke={colors.primary}
            strokeWidth={2.5}
            dot={{ r: 3, fill: colors.primary }}
            activeDot={{ r: 5 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

/** How random the looked-up names were: normal vs flagged. */
export function EntropyChart({ hist, colors }: { hist: EntropyHistogram; colors: Colors }) {
  const data = useMemo(
    () =>
      hist.centers.map((c, i) => ({
        score: c,
        normal: hist.normal[i] ?? 0,
        flagged: hist.flagged[i] ?? 0,
      })),
    [hist],
  );

  if (!data.length) return <p className="muted">No name data to show.</p>;

  return (
    <div className="chart-box">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ left: 0, right: 16, top: 8, bottom: 4 }} barGap={0} barCategoryGap="10%">
          <CartesianGrid vertical={false} stroke={colors.grid} />
          <XAxis
            dataKey="score"
            tick={axisStyle(colors)}
            stroke={colors.grid}
            label={{ value: "randomness score", position: "insideBottom", offset: -2, fill: colors.text, fontSize: 11 }}
          />
          <YAxis tick={axisStyle(colors)} stroke={colors.grid} allowDecimals={false} />
          <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-2)" }} />
          <Legend wrapperStyle={{ fontSize: 12, color: colors.text }} />
          <Bar dataKey="normal" name="normal names" fill={colors.normal} stackId="e" />
          <Bar dataKey="flagged" name="flagged names" fill={colors.flagged} stackId="e" radius={[3, 3, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
