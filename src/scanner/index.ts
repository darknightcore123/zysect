import { ScanResult, Finding } from '../types';
import { detectLanguage } from '../utils/language';
import { parseCode } from '../utils/ast';
import { checkApiKeys } from './check_api_keys';
import { checkRateLimiting } from './check_rate_limiting';
import { checkRlsConfig } from './check_rls_config';
import { checkAuthMiddleware } from './check_auth_middleware';
import { checkSqlInjection } from './check_sql_injection';
import { checkInputLimits } from './check_input_limits';
import { checkAgentPermissions } from './check_agent_permissions';

const CONFIDENCE_THRESHOLD = 95;

type CheckFn = (
  tree: import('tree-sitter').Tree,
  code: string,
  language: import('../types').SupportedLanguage,
  filePath: string,
) => Finding[];

const ALL_CHECKS: CheckFn[] = [
  checkApiKeys,
  checkRateLimiting,
  checkRlsConfig,
  checkAuthMiddleware,
  checkSqlInjection,
  checkInputLimits,
  checkAgentPermissions,
];

export interface RunScanOptions {
  filePath: string;
  fileContent: string;
  /** Run only a specific rule (e.g. 'check_api_keys'). Runs all if omitted. */
  rule?: string;
}

export function runScan(options: RunScanOptions): ScanResult {
  const { filePath, fileContent, rule } = options;
  const start = Date.now();

  const language = detectLanguage(filePath);

  if (language === 'unknown') {
    return {
      findings: [],
      language: 'unknown',
      scan_time_ms: Date.now() - start,
      file_path: filePath,
    };
  }

  const tree = parseCode(fileContent, language);

  if (!tree) {
    return {
      findings: [],
      language,
      scan_time_ms: Date.now() - start,
      file_path: filePath,
    };
  }

  const checksToRun = rule
    ? ALL_CHECKS.filter(fn => fn.name === rule || fn.name.replace('check', 'check_').replace(/([A-Z])/g, (_, c: string) => '_' + c.toLowerCase()) === rule)
    : ALL_CHECKS;

  const rawFindings: Finding[] = [];

  for (const check of checksToRun) {
    try {
      const found = check(tree, fileContent, language, filePath);
      rawFindings.push(...found);
    } catch {
      // Silently skip a failing check — never crash the IDE
    }
  }

  // Enforce confidence gate
  const findings = rawFindings.filter(f => f.confidence >= CONFIDENCE_THRESHOLD);

  return {
    findings,
    language,
    scan_time_ms: Date.now() - start,
    file_path: filePath,
  };
}
