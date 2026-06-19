import Parser from 'tree-sitter';
import { Finding, SupportedLanguage } from '../types';
import { walkNodes } from '../utils/ast';
import { isTestFile } from '../utils/language';

// Method names that accept raw SQL or raw query strings.
const QUERY_METHOD_NAMES = new Set([
  'query', 'execute', 'exec', 'run',
  'raw', 'rawQuery', 'queryRaw',
  'prepare', 'all', 'get',
  // ORM escape hatches
  'whereRaw', 'havingRaw', 'orderByRaw', 'groupByRaw', 'fromRaw',
  'selectRaw',
]);

// Identifiers that suggest a value came from external input.
const USER_INPUT_PATTERNS = [
  /^req\./,
  /^request\./,
  /^body\./,
  /^params\./,
  /^query\./,
  /^input\./,
  /^data\./,
  /^form\./,
  /^event\.body/,
  /^ctx\./,
];

function looksLikeUserInput(varText: string): boolean {
  return USER_INPUT_PATTERNS.some(rx => rx.test(varText));
}

// Recursively check if a template_string has any substitution expressions.
function hasInterpolation(node: Parser.SyntaxNode): boolean {
  for (const child of walkNodes(node)) {
    if (child.type === 'template_substitution') return true;
  }
  return false;
}

// Collect all interpolated sub-expressions from a template string.
function getInterpolatedExpressions(node: Parser.SyntaxNode): Parser.SyntaxNode[] {
  const exprs: Parser.SyntaxNode[] = [];
  for (const child of node.children) {
    if (child.type === 'template_substitution') {
      const inner = child.namedChild(0);
      if (inner) exprs.push(inner);
    }
  }
  return exprs;
}

// Walk up to find if this template literal is passed to a query method.
function getContainingQueryCall(
  node: Parser.SyntaxNode,
): Parser.SyntaxNode | null {
  let current: Parser.SyntaxNode | null = node.parent;
  let depth = 0;

  while (current && depth < 5) {
    if (current.type === 'arguments') {
      const callNode = current.parent;
      if (callNode?.type === 'call_expression') {
        const fn = callNode.childForFieldName('function');
        const prop =
          fn?.type === 'member_expression'
            ? fn.childForFieldName('property')?.text
            : fn?.text;
        if (prop && QUERY_METHOD_NAMES.has(prop)) return callNode;
      }
    }
    current = current.parent;
    depth++;
  }

  return null;
}

export function checkSqlInjection(
  tree: Parser.Tree,
  _code: string,
  language: SupportedLanguage,
  filePath: string,
): Finding[] {
  if (!['javascript', 'typescript', 'tsx', 'python'].includes(language)) return [];
  if (isTestFile(filePath)) return [];

  const findings: Finding[] = [];

  for (const node of walkNodes(tree.rootNode)) {
    // JS/TS: template strings passed to query methods
    if (node.type === 'template_string' && language !== 'python') {
      if (!hasInterpolation(node)) continue;

      const queryCall = getContainingQueryCall(node);
      if (!queryCall) continue;

      const interpolatedExprs = getInterpolatedExpressions(node);

      // Boost confidence if any interpolated value looks like user input
      const hasUserInputExpr = interpolatedExprs.some(e =>
        looksLikeUserInput(e.text),
      );

      const confidence = hasUserInputExpr ? 98 : 95;

      findings.push({
        rule: 'check_sql_injection',
        severity: 'P0',
        message: `SQL injection risk: template literal with variable interpolation passed to \`${
          queryCall.childForFieldName('function')?.childForFieldName('property')?.text ?? 'query'
        }()\`. Never concatenate variables into SQL strings.`,
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
        confidence,
        snippet: node.text.slice(0, 120),
        fix_suggestion:
          'Use parameterized queries: `db.query("SELECT * FROM users WHERE id = $1", [userId])` — never interpolate variables into SQL strings.',
      });
    }

    // JS/TS: binary string concatenation in query calls (e.g. "SELECT ... WHERE id = " + id)
    if (node.type === 'binary_expression' && language !== 'python') {
      const operator = node.childForFieldName('operator')?.text;
      if (operator !== '+') continue;

      const queryCall = getContainingQueryCall(node);
      if (!queryCall) continue;

      // Only flag if at least one operand is a string literal (indicates SQL fragment)
      const left = node.childForFieldName('left');
      const right = node.childForFieldName('right');
      const hasSqlFragment =
        (left?.type === 'string' && /\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|INTO)\b/i.test(left.text)) ||
        (right?.type === 'string' && /\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|INTO)\b/i.test(right.text));

      if (!hasSqlFragment) continue;

      findings.push({
        rule: 'check_sql_injection',
        severity: 'P0',
        message: `SQL injection risk: string concatenation with a SQL fragment passed to a query method.`,
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
        confidence: 96,
        snippet: node.text.slice(0, 120),
        fix_suggestion:
          'Use parameterized queries. Replace string concatenation with positional parameters: `db.query("SELECT * FROM t WHERE col = $1", [value])`.',
      });
    }

    // Python: f-strings or % formatting passed to execute/query
    if (node.type === 'string' && language === 'python') {
      // Python f-strings have children that include `interpolation` nodes
      const hasFStringInterp = node.children.some(
        c => c.type === 'interpolation',
      );
      if (!hasFStringInterp) continue;

      const queryCall = getContainingQueryCall(node);
      if (!queryCall) continue;

      findings.push({
        rule: 'check_sql_injection',
        severity: 'P0',
        message: `SQL injection risk: f-string with variable interpolation passed to a database execute method.`,
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
        confidence: 96,
        snippet: node.text.slice(0, 120),
        fix_suggestion:
          'Use parameterized queries: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))` — never use f-strings in SQL.',
      });
    }
  }

  return findings;
}
