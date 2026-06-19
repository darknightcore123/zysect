export type Severity = 'P0' | 'P1' | 'P2';

export interface Finding {
  rule: string;
  severity: Severity;
  message: string;
  line: number;       // 1-based
  column: number;     // 0-based
  confidence: number; // 0–100
  snippet: string;
  fix_suggestion: string;
}

export interface ScanResult {
  findings: Finding[];
  language: string;
  scan_time_ms: number;
  file_path: string;
}

export type SupportedLanguage =
  | 'javascript'
  | 'typescript'
  | 'tsx'
  | 'python'
  | 'go'
  | 'java'
  | 'ruby'
  | 'unknown';
