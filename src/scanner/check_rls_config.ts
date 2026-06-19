import Parser from 'tree-sitter';
import { Finding, SupportedLanguage } from '../types';
import { walkNodes, extractStringValue, getImportSources } from '../utils/ast';
import { isServerSideFile, isAdminOrMigrationScript, isPubliclyIntendedRoute } from '../utils/language';

// Supabase write operations — reads are lower risk, writes without RLS are P0.
const WRITE_METHODS = new Set(['insert', 'upsert', 'update', 'delete']);

// Patterns that indicate the developer IS filtering by the current user's id.
const USER_FILTER_PATTERNS = [
  /user_?id/i,
  /owner_?id/i,
  /created_?by/i,
  /auth\.uid/i,
  /getUser/i,
  /getSession/i,
];

function hasUserFilter(callChainText: string): boolean {
  return USER_FILTER_PATTERNS.some(rx => rx.test(callChainText));
}

// Walk up from a node to reconstruct the full method-chain text up to N levels.
function getCallChainText(node: Parser.SyntaxNode, maxAncestors = 12): string {
  let current: Parser.SyntaxNode | null = node;
  let depth = 0;
  while (current && depth < maxAncestors) {
    if (
      current.type === 'expression_statement' ||
      current.type === 'return_statement' ||
      current.type === 'variable_declarator'
    ) {
      return current.text;
    }
    current = current.parent;
    depth++;
  }
  return node.text;
}

export function checkRlsConfig(
  tree: Parser.Tree,
  _code: string,
  language: SupportedLanguage,
  filePath: string,
): Finding[] {
  if (!['javascript', 'typescript', 'tsx'].includes(language)) return [];
  if (isAdminOrMigrationScript(filePath)) return [];
  if (isPubliclyIntendedRoute(filePath)) return [];

  const findings: Finding[] = [];
  const imports = getImportSources(tree);
  const usesSupabase = imports.some(
    s => s.includes('@supabase/supabase-js') || s.includes('@supabase/ssr'),
  );
  if (!usesSupabase) return [];

  const serverSide = isServerSideFile(filePath);

  for (const node of walkNodes(tree.rootNode)) {
    // Find `.from('tableName')` member-expression calls
    if (node.type !== 'call_expression') continue;

    const fn = node.childForFieldName('function');
    if (!fn || fn.type !== 'member_expression') continue;

    const method = fn.childForFieldName('property');
    if (method?.text !== 'from') continue;

    const args = node.childForFieldName('arguments');
    const firstArg = args?.namedChild(0);
    if (!firstArg || firstArg.type !== 'string') continue;

    const tableName = extractStringValue(firstArg);
    const chainText = getCallChainText(node);

    // Determine if a write method is in this chain
    const isWrite = WRITE_METHODS.has(
      (() => {
        let current: Parser.SyntaxNode | null = node.parent;
        let depth = 0;
        while (current && depth < 8) {
          if (current.type === 'call_expression') {
            const m = current.childForFieldName('function');
            const prop = m?.childForFieldName?.('property');
            if (prop && WRITE_METHODS.has(prop.text)) return prop.text;
          }
          current = current.parent;
          depth++;
        }
        return '';
      })(),
    );

    // Check: service_role client being used client-side
    const isServiceRoleContext =
      /service_role/i.test(chainText) ||
      /SUPABASE_SERVICE_ROLE/i.test(chainText);

    if (isServiceRoleContext && !serverSide) {
      findings.push({
        rule: 'check_rls_config',
        severity: 'P0',
        message: `Supabase service_role client detected in a non-server file. The service role key bypasses ALL RLS policies.`,
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
        confidence: 97,
        snippet: chainText.slice(0, 160),
        fix_suggestion:
          'Never use the service_role key in client-side or edge code. Use the anon key with proper RLS policies instead.',
      });
      continue;
    }

    // Check: write to a table without a user-ownership filter
    if (isWrite && !hasUserFilter(chainText)) {
      findings.push({
        rule: 'check_rls_config',
        severity: 'P0',
        message: `Write to table "${tableName}" has no user-ownership filter (.eq("user_id", ...)). If RLS is not enabled this allows any user to overwrite any row.`,
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
        confidence: 95,
        snippet: chainText.slice(0, 160),
        fix_suggestion:
          `Either enable RLS with a policy like "auth.uid() = user_id" on table "${tableName}", or add .eq("user_id", session.user.id) to every write query.`,
      });
    }
  }

  return findings;
}
