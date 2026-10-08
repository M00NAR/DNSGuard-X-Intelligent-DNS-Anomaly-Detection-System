import type { ReactNode } from "react";
import type { Severity } from "../types";
import { InfoIcon } from "../icons";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const cls = severity.toLowerCase();
  return (
    <span className={`badge ${cls}`}>
      <span className={`dot ${cls}`} />
      {severity}
    </span>
  );
}

/** A labelled card section with an optional one-line description. */
export function Section({
  title,
  subtitle,
  children,
  icon,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  icon?: ReactNode;
}) {
  return (
    <section className="card card-pad">
      <div className="section-title">
        {icon}
        <h2>{title}</h2>
      </div>
      {subtitle && <p className="section-sub">{subtitle}</p>}
      {children}
    </section>
  );
}

/** Native tooltip via title attribute, shown as a small info glyph. */
export function Hint({ text }: { text: string }) {
  return (
    <span className="muted" title={text} style={{ display: "inline-flex", cursor: "help" }}>
      <InfoIcon />
    </span>
  );
}
