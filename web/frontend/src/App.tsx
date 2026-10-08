import { useCallback, useMemo, useRef, useState } from "react";
import { analyzeFile, analyzeSample } from "./api";
import { CategoryBar, EntropyChart, Timeline } from "./components/Charts";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Metrics } from "./components/Metrics";
import { Section } from "./components/common";
import { TopHosts } from "./components/TopHosts";
import { WarningsTable } from "./components/WarningsTable";
import { HelpIcon, MoonIcon, PlayIcon, ShieldIcon, SunIcon, UploadIcon } from "./icons";
import { chartColors, useTheme } from "./theme";
import type { AnalysisResult } from "./types";

export default function App() {
  const { theme, toggle } = useTheme();
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  // Re-read chart colours whenever the theme flips.
  const colors = useMemo(() => chartColors(theme), [theme]);

  const run = useCallback(async (fn: () => Promise<AnalysisResult>) => {
    setLoading(true);
    setError(null);
    try {
      setResult(await fn());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed.");
    } finally {
      setLoading(false);
    }
  }, []);

  const onSample = () => run(() => analyzeSample());
  const onFile = (file: File) => run(() => analyzeFile(file));

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) onFile(file);
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark"><ShieldIcon width={22} height={22} /></span>
          <div>
            <h1>DNSGuard-X</h1>
            <p>Reviews DNS lookups and flags the ones that match known attack patterns.</p>
          </div>
        </div>
        <button
          className="btn icon-btn btn-ghost"
          onClick={toggle}
          aria-label={theme === "dark" ? "Switch to day theme" : "Switch to night theme"}
          title={theme === "dark" ? "Switch to day theme" : "Switch to night theme"}
        >
          {theme === "dark" ? <SunIcon /> : <MoonIcon />}
        </button>
      </header>

      <div className="card source">
        <button className="btn btn-primary" onClick={onSample} disabled={loading}>
          <PlayIcon width={16} height={16} /> Run the sample capture
        </button>
        <label
          className={`dropzone${dragging ? " drag" : ""}`}
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
        >
          <UploadIcon width={16} height={16} />
          <span>Drop a .pcap file here, or click to choose</span>
          <input
            ref={fileInput}
            type="file"
            accept=".pcap,.pcapng,.cap"
            hidden
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) onFile(f);
              e.target.value = "";
            }}
          />
        </label>
        <div className="spacer" />
        {result && !loading && <span className="source-tag">Source: {result.source}</span>}
      </div>

      {loading && (
        <div className="banner"><span className="spinner" /> &nbsp;Checking the capture…</div>
      )}
      {error && <div className="banner error" role="alert">{error}</div>}

      {!result && !loading && !error && (
        <div className="card card-pad empty">
          Run the sample capture or drop in your own .pcap file to begin. No traffic is
          sent — files are only read and analysed.
        </div>
      )}

      {result && !loading && (
        <ErrorBoundary>
          <Metrics stats={result.stats} />

          {result.warnings.length === 0 ? (
            <div className="card card-pad empty">Nothing suspicious was found in this capture.</div>
          ) : (
            <div className="stack-sm">
              <div className="grid-2">
                <Section title="Warnings by category" subtitle="How many warnings of each kind were raised.">
                  <CategoryBar warnings={result.warnings} colors={colors} />
                </Section>
                <Section title="Warnings over time" subtitle="When warnings appeared during the capture.">
                  <Timeline warnings={result.warnings} colors={colors} />
                </Section>
              </div>

              <Section
                title="How random the looked-up names were"
                subtitle="Everyday names score low; scrambled or machine-made names score high. Flagged names are shown on top."
              >
                <EntropyChart hist={result.entropyHistogram} colors={colors} />
              </Section>

              <Section title="Most active hosts" subtitle="The computers that raised the most warnings.">
                <TopHosts warnings={result.warnings} />
              </Section>

              <Section
                title="What these categories mean"
                subtitle="Plain-language explanation of each warning type found."
                icon={<HelpIcon width={17} height={17} />}
              >
                <div className="help-list">
                  {Object.entries(result.categoryHelp).map(([name, text]) => (
                    <div className="row" key={name}>
                      <span className="name">{name}</span>
                      <span className="muted">{text}</span>
                    </div>
                  ))}
                </div>
              </Section>

              <Section title="All warnings" subtitle="Filter by category or severity and read the reason for each.">
                <WarningsTable warnings={result.warnings} />
              </Section>
            </div>
          )}
        </ErrorBoundary>
      )}
    </div>
  );
}
