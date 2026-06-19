import Parser from 'tree-sitter';
import { Finding, SupportedLanguage } from '../types';
import { walkNodes } from '../utils/ast';
import { isPubliclyIntendedRoute, isAuthEndpoint } from '../utils/language';

// Next.js App Router HTTP-method exports that define route handlers.
const NEXT_ROUTE_EXPORTS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

// Functions that verify the current user's identity.
const AUTH_CHECK_PATTERNS = [
  /\bauth\s*\(/,
  /\bgetSession\s*\(/,
  /\bgetServerSession\s*\(/,
  /\bcurrentUser\s*\(/,
  /\bverifyToken\s*\(/,
  /\bverifyJwt\s*\(/,
  /\bauthenticate\s*\(/,
  /\bgetUser\s*\(/,
  /\.auth\.getUser\s*\(/,
  /\.auth\.getSession\s*\(/,
  /requireAuth/,
  /withAuth/,
  /isAuthenticated/,
  /checkAuth/,
];

function containsAuthCheck(fnBody: string): boolean {
  return AUTH_CHECK_PATTERNS.some(rx => rx.test(fnBody));
}

// Find the function body text for an exported function/const declaration.
function extractExportedFunctionBody(
  exportNode: Parser.SyntaxNode,
): { name: string; bodyText: string; line: number; column: number } | null {
  // export async function GET(...) { ... }
  // export const POST = async (req) => { ... }
  for (const node of walkNodes(exportNode)) {
    if (
      node.type === 'function_declaration' ||
      node.type === 'function'
    ) {
      const nameNode = node.childForFieldName('name');
      const name = nameNode?.text ?? '';
      if (NEXT_ROUTE_EXPORTS.has(name)) {
        const body = node.childForFieldName('body');
        return {
          name,
          bodyText: body?.text ?? node.text,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
        };
      }
    }

    if (node.type === 'variable_declarator') {
      const nameNode = node.childForFieldName('name');
      const name = nameNode?.text ?? '';
      if (!NEXT_ROUTE_EXPORTS.has(name)) continue;

      const value = node.childForFieldName('value');
      if (!value) continue;

      const bodyNode =
        value.type === 'arrow_function' || value.type === 'function_expression'
          ? value.childForFieldName('body')
          : null;

      return {
        name,
        bodyText: bodyNode?.text ?? value.text,
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
      };
    }
  }
  return null;
}

export function checkAuthMiddleware(
  tree: Parser.Tree,
  code: string,
  language: SupportedLanguage,
  filePath: string,
): Finding[] {
  if (!['javascript', 'typescript', 'tsx'].includes(language)) return [];
  if (isPubliclyIntendedRoute(filePath)) return [];
  if (isAuthEndpoint(filePath)) return [];

  const findings: Finding[] = [];

  // Detect 'use server' directive (Next.js server actions)
  const hasUseServerDirective = /^\s*['"]use server['"]/m.test(code);

  // If this is a 'use server' file, every exported async function needs an auth check.
  if (hasUseServerDirective) {
    // page.tsx/page.ts are React server components, not callable server actions.
    // Auth on pages is enforced at the middleware or layout level — we can't see that.
    if (/\/page\.(tsx?|jsx?)$/.test(filePath.replace(/\\/g, '/'))) return findings;

    for (const node of walkNodes(tree.rootNode)) {
      if (
        node.type !== 'function_declaration' &&
        node.type !== 'variable_declarator'
      ) continue;

      let funcName = '';
      let bodyText = '';
      let line = node.startPosition.row + 1;
      const column = node.startPosition.column;

      if (node.type === 'function_declaration') {
        funcName = node.childForFieldName('name')?.text ?? '';
        bodyText = node.childForFieldName('body')?.text ?? '';
      } else {
        funcName = node.childForFieldName('name')?.text ?? '';
        const value = node.childForFieldName('value');
        // Only flag callable exports. String/boolean config exports (e.g. Next.js
        // `export const dynamic = 'force-dynamic'`) are not server actions.
        if (!value || (value.type !== 'arrow_function' && value.type !== 'function_expression')) continue;
        bodyText = value.childForFieldName('body')?.text ?? value.text;
      }

      if (!funcName || !bodyText) continue;

      // Only check exported functions
      const parent = node.parent;
      const isExported =
        parent?.type === 'export_statement' ||
        parent?.type === 'lexical_declaration' && parent.parent?.type === 'export_statement';

      if (!isExported) continue;
      if (containsAuthCheck(bodyText)) continue;

      findings.push({
        rule: 'check_auth_middleware',
        severity: 'P0',
        message: `Server action \`${funcName}\` in a 'use server' file has no auth check. Any client can invoke this action.`,
        line,
        column,
        confidence: 95,
        snippet: `export async function ${funcName}(...)`,
        fix_suggestion:
          `Add at the top of ${funcName}: \`const { data: { user } } = await supabase.auth.getUser(); if (!user) throw new Error("Unauthorized");\``,
      });
    }
    return findings;
  }

  // Next.js App Router route handler file (route.ts / route.js)
  const isRouteFile = /route\.(ts|js|tsx)$/.test(filePath.replace(/\\/g, '/'));
  if (!isRouteFile) return findings;

  for (const node of walkNodes(tree.rootNode)) {
    if (node.type !== 'export_statement') continue;

    const info = extractExportedFunctionBody(node);
    if (!info) continue;

    if (containsAuthCheck(info.bodyText)) continue;

    // Only flag non-GET handlers (GET can be public) unless they access user-specific data
    const isWrite = info.name !== 'GET' && info.name !== 'HEAD' && info.name !== 'OPTIONS';
    if (!isWrite) continue;

    findings.push({
      rule: 'check_auth_middleware',
      severity: 'P0',
      message: `Next.js route handler \`${info.name}\` in ${filePath.split(/[\\/]/).pop()} has no authentication check. Unauthenticated callers can mutate data.`,
      line: info.line,
      column: info.column,
      confidence: 96,
      snippet: `export async function ${info.name}(request: Request) { ... }`,
      fix_suggestion:
        `Add at the start of \`${info.name}\`: \`const { data: { user }, error } = await supabase.auth.getUser(); if (error || !user) return Response.json({ error: "Unauthorized" }, { status: 401 });\``,
    });
  }

  return findings;
}
