import Parser from 'tree-sitter';
import { Finding, SupportedLanguage } from '../types';
import { walkNodes, extractStringValue, getStringNodeTypes, getVariableContext } from '../utils/ast';
import { isTestFile } from '../utils/language';

interface KeyPattern {
  provider: string;
  pattern: RegExp;
  baseConfidence: number;
  severity: 'P0' | 'P1' | 'P2';
}

const KEY_PATTERNS: KeyPattern[] = [
  { provider: 'OpenAI',                    pattern: /^sk-[a-zA-Z0-9]{48}$/,                                  baseConfidence: 97, severity: 'P0' },
  { provider: 'OpenAI Project Key',        pattern: /^sk-proj-[a-zA-Z0-9_\-]{40,}$/,                        baseConfidence: 97, severity: 'P0' },
  { provider: 'Anthropic',                 pattern: /^sk-ant-[a-zA-Z0-9_\-]{40,}$/,                         baseConfidence: 97, severity: 'P0' },
  { provider: 'AWS Access Key ID',         pattern: /^AKIA[0-9A-Z]{16}$/,                                   baseConfidence: 98, severity: 'P0' },
  { provider: 'Google Cloud API Key',      pattern: /^AIzaSy[a-zA-Z0-9_\-]{33}$/,                          baseConfidence: 97, severity: 'P0' },
  { provider: 'Stripe Live Secret Key',    pattern: /^sk_live_[a-zA-Z0-9]{24,}$/,                          baseConfidence: 99, severity: 'P0' },
  { provider: 'Stripe Test Secret Key',    pattern: /^sk_test_[a-zA-Z0-9]{24,}$/,                          baseConfidence: 96, severity: 'P1' },
  { provider: 'GitHub Personal Token',     pattern: /^ghp_[a-zA-Z0-9]{36}$/,                               baseConfidence: 97, severity: 'P0' },
  { provider: 'GitHub App Token',          pattern: /^github_pat_[a-zA-Z0-9_]{82,}$/,                      baseConfidence: 98, severity: 'P0' },
  { provider: 'Twilio',                    pattern: /^SK[0-9a-fA-F]{32}$/,                                  baseConfidence: 96, severity: 'P0' },
  { provider: 'SendGrid',                  pattern: /^SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}$/,       baseConfidence: 97, severity: 'P0' },
  { provider: 'Slack Token',               pattern: /^xox[bpoa]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}$/, baseConfidence: 97, severity: 'P0' },
  { provider: 'Hugging Face Token',        pattern: /^hf_[a-zA-Z0-9]{34,}$/,                               baseConfidence: 96, severity: 'P0' },
  { provider: 'Pinecone API Key',          pattern: /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/, baseConfidence: 60, severity: 'P1' }, // UUID — needs var name boost
  { provider: 'Replicate API Token',       pattern: /^r8_[a-zA-Z0-9]{40}$/,                                baseConfidence: 97, severity: 'P0' },
];

const SENSITIVE_VAR_NAMES = [
  /api[_\-]?key/i,
  /api[_\-]?secret/i,
  /secret[_\-]?key/i,
  /access[_\-]?token/i,
  /auth[_\-]?token/i,
  /private[_\-]?key/i,
  /service[_\-]?role/i,
  /bearer[_\-]?token/i,
  /password/i,
  /credentials/i,
  /client[_\-]?secret/i,
];

export function checkApiKeys(
  tree: Parser.Tree,
  _code: string,
  language: SupportedLanguage,
  filePath: string,
): Finding[] {
  const findings: Finding[] = [];
  const stringTypes = getStringNodeTypes(language);
  const testFilePenalty = isTestFile(filePath) ? 10 : 0;

  for (const node of walkNodes(tree.rootNode)) {
    if (!stringTypes.includes(node.type)) continue;

    const value = extractStringValue(node);
    if (value.length < 16) continue;

    for (const kp of KEY_PATTERNS) {
      if (!kp.pattern.test(value)) continue;

      const varContext = getVariableContext(node);
      let confidence = kp.baseConfidence - testFilePenalty;

      // Boost when variable name is also clearly sensitive
      if (varContext && SENSITIVE_VAR_NAMES.some(rx => rx.test(varContext))) {
        confidence = Math.min(100, confidence + 2);
      }

      // UUID-style patterns need the variable name to reach threshold
      if (kp.provider === 'Pinecone API Key') {
        if (!varContext || !SENSITIVE_VAR_NAMES.some(rx => rx.test(varContext))) continue;
        confidence = 96;
      }

      if (confidence < 95) continue;

      const masked = value.slice(0, 6) + '...' + value.slice(-4);
      const varInfo = varContext ? ` (assigned to \`${varContext}\`)` : '';
      const envName = varContext
        ? varContext.toUpperCase().replace(/[^A-Z0-9]/g, '_')
        : 'API_KEY';

      findings.push({
        rule: 'check_api_keys',
        severity: kp.severity,
        message: `Hardcoded ${kp.provider} key detected${varInfo}. Secrets committed to source are irreversible.`,
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
        confidence,
        snippet: `"${masked}"`,
        fix_suggestion: `Replace with process.env.${envName} and add ${envName}=<value> to your .env file (never commit .env).`,
      });
      break; // first matching pattern wins — don't double-report the same string
    }
  }

  return findings;
}
