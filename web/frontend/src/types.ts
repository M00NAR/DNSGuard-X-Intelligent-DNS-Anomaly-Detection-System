export type Severity = "High" | "Medium" | "Low";

export interface Warning {
  timestamp: number;
  src_ip: string;
  domain: string;
  attack_type: string;
  severity: Severity;
  detector_id: string;
  hit_count: number;
  reason: string;
}

export interface Stats {
  packets?: number;
  lookups_checked: number;
  queries_seen?: number;
  responses_seen?: number;
  whitelisted?: number;
  warnings: number;
  matches: number;
  hosts: number;
}

export interface EntropyHistogram {
  centers: number[];
  normal: number[];
  flagged: number[];
}

export interface AnalysisResult {
  stats: Stats;
  warnings: Warning[];
  entropyHistogram: EntropyHistogram;
  categoryHelp: Record<string, string>;
  source: string;
}
