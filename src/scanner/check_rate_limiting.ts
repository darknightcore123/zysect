import Parser from 'tree-sitter';
import { Finding, SupportedLanguage } from '../types';
import { walkNodes, extractStringValue, getStringNodeTypes, getImportSources } from '../utils/ast';
import { isTestFile } from '../utils/language';

// Route paths that process authentication — highest risk if unprotected.
const AUTH_ROUTE_PATTERNS = [
  /\/auth\b/i,
  /\/login\b/i,
  /\/signin\b/i,
  /\/signup\b/i,
  /\/register\b/i,
  /\/forgot.?password/i,
  /\/reset.?password/i,
  /\/change.?password/i,
  /\/verify.?email/i,
  /\/resend.?otp/i,
  /\/2fa\b/i,
  /\/mfa\b/i,
  /\/token\b/i,
  /\/refresh\b/i,
];

const RATE_LIMITER_PACKAGES = [
  'express-rate-limit',
  'rate-limiter-flexible',
  '@upstash/ratelimit',
  'bottleneck',
  'express-slow-down',
  'p-throttle',
  'limiter',
  'node-rate-limiter-flexible',
];

// Identifiers that suggest a rate limiter is already wired in.
const RATE_LIMITER_CALL_PATTERNS = [
  /rateLimit/i,
  /rateLimiter/i,
  /limiter\.consume/i,
  /ratelimit\.limit/i,
  /throttle/i,
  /slowDown/i,
];

function hasRateLimiterInScope(tree: Parser.Tree): boolean {
  // 1. Check imports
  const imports = getImportSources(tree);
  if (RATE_LIMITER_PACKAGES.some(pkg => imports.includes(pkg))) return true;

  // 2. Check for limiter-style call expressions in the file
  for (const node of walkNodes(tree.rootNode)) {
    if (node.type === 'identifier' || node.type === 'property_identifier') {
      if (RATE_LIMITER_CALL_PATTERNS.some(rx => rx.test(node.text))) return true;
    }
  }

  return false;
}

export function checkRateLimiting(
  tree: Parser.Tree,
  _code: string,
  language: SupportedLanguage,
  filePath: string,
): Finding[] {
  if (!['javascript', 'typescript', 'tsx'].includes(language)) return [];
  if (isTestFile(filePath)) return [];

  const findings: Finding[] = [];
  const stringTypes = getStringNodeTypes(language);
  const hasLimiter = hasRateLimiterInScope(tree);

  if (hasLimiter) return [];

  // Collect auth route string literals in this file
  const authRouteNodes: Parser.SyntaxNode[] = [];

  for (const node of walkNodes(tree.rootNode)) {
    if (!stringTypes.includes(node.type)) continue;
    const value = extractStringValue(node);
    if (AUTH_ROUTE_PATTERNS.some(rx => rx.test(value))) {
      authRouteNodes.push(node);
    }
  }

  for (const routeNode of authRouteNodes) {
    // Walk up to find the containing call expression (route registration)
    let callNode: Parser.SyntaxNode | null = routeNode.parent;
    while (callNode && callNode.type !== 'call_expression' && callNode.type !== 'statement_block') {
      callNode = callNode.parent;
    }

    if (!callNode || callNode.type !== 'call_expression') continue;

    const fnNode = callNode.childForFieldName('function');
    const isRouteRegistration =
      fnNode?.type === 'member_expression' &&
      /^(get|post|put|patch|delete|all|use)$/i.test(
        fnNode.childForFieldName('property')?.text ?? '',
      );

    if (!isRouteRegistration) continue;

    const routePath = extractStringValue(routeNode);
    findings.push({
      rule: 'check_rate_limiting',
      severity: 'P0',
      message: `Auth route "${routePath}" has no rate limiter. Brute-force and credential-stuffing attacks will succeed.`,
      line: callNode.startPosition.row + 1,
      column: callNode.startPosition.column,
      confidence: 96,
      snippet: callNode.text.slice(0, 120),
      fix_suggestion:
        'Add express-rate-limit: `import rateLimit from "express-rate-limit"` then pass `rateLimit({ windowMs: 15*60*1000, max: 10 })` as middleware before your handler.',
    });
  }

  return findings;
}
