import Parser from 'tree-sitter';
import { Finding, SupportedLanguage } from '../types';
import { walkNodes, extractStringValue, getStringNodeTypes, getVariableContext, getImportSources } from '../utils/ast';
import { isServerSideFile } from '../utils/language';

// Overly broad IAM action/resource wildcards.
const WILDCARD_PATTERNS = [/^\*$/, /^.*:\*$/, /^arn:aws:\*/, /^arn:.*:\*$/];

// Service account / admin SDK variable names that should never appear client-side.
const ADMIN_VAR_PATTERNS = [
  /service_?role/i,
  /service_?account/i,
  /admin_?sdk/i,
  /firebase.?admin/i,
  /GOOGLE_APPLICATION_CREDENTIALS/i,
];

// Firebase admin, AWS SDK admin credentials, GCP service accounts.
const ADMIN_PACKAGE_NAMES = [
  'firebase-admin',
  'aws-sdk',
  '@aws-sdk/client-iam',
  '@aws-sdk/client-sts',
  'google-auth-library',
  '@google-cloud/storage',
];

export function checkAgentPermissions(
  tree: Parser.Tree,
  _code: string,
  language: SupportedLanguage,
  filePath: string,
): Finding[] {
  if (!['javascript', 'typescript', 'tsx', 'python'].includes(language)) return [];

  const findings: Finding[] = [];
  const stringTypes = getStringNodeTypes(language);
  const imports = getImportSources(tree);
  const serverSide = isServerSideFile(filePath);

  const usesAdminSdk = ADMIN_PACKAGE_NAMES.some(pkg => imports.includes(pkg));

  // 1. Wildcard IAM permissions in any string literal
  for (const node of walkNodes(tree.rootNode)) {
    if (!stringTypes.includes(node.type)) continue;

    const value = extractStringValue(node);
    if (!WILDCARD_PATTERNS.some(rx => rx.test(value))) continue;

    // Only flag when inside an object that looks like an IAM policy
    let inPolicyContext = false;
    let current: Parser.SyntaxNode | null = node.parent;
    let depth = 0;
    while (current && depth < 10) {
      if (current.type === 'object' || current.type === 'dictionary') {
        const objText = current.text;
        if (
          /\bEffect\b/.test(objText) ||
          /\bAction\b/.test(objText) ||
          /\bResource\b/.test(objText) ||
          /\bprincipal\b/i.test(objText) ||
          /\bpermissions\b/i.test(objText)
        ) {
          inPolicyContext = true;
          break;
        }
      }
      current = current.parent;
      depth++;
    }

    if (!inPolicyContext) continue;

    const varContext = getVariableContext(node);
    const inAction = varContext
      ? /\bAction\b|\bPermission\b/.test(varContext)
      : false;

    findings.push({
      rule: 'check_agent_permissions',
      severity: 'P0',
      message: `Wildcard permission "${value}" detected in what appears to be an IAM/permissions policy. AI agents frequently grant \`*\` to unblock themselves.`,
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
      confidence: inAction ? 97 : 95,
      snippet: `"${value}"`,
      fix_suggestion:
        'Apply least-privilege: enumerate only the exact actions/resources this role requires. Replace "*" with the specific service action, e.g. "s3:GetObject".',
    });
  }

  // 2. Admin/service-role credentials used in client-side files
  if (usesAdminSdk && !serverSide) {
    // Flag the import itself
    for (const node of walkNodes(tree.rootNode)) {
      if (node.type !== 'import_statement' && node.type !== 'import_declaration') continue;
      const source = node.childForFieldName('source');
      if (!source) continue;
      const pkg = extractStringValue(source);
      if (!ADMIN_PACKAGE_NAMES.includes(pkg)) continue;

      findings.push({
        rule: 'check_agent_permissions',
        severity: 'P0',
        message: `Admin SDK package "${pkg}" imported in a non-server file. Admin credentials exposed to the browser grant full bypass of all security rules.`,
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
        confidence: 97,
        snippet: node.text.slice(0, 100),
        fix_suggestion:
          `Move all ${pkg} usage to a server-side file (e.g. /app/api/ or /server/). Never expose admin SDKs or service-account keys to the client bundle.`,
      });
      break; // one finding per package per file is enough
    }
  }

  // 3. Sensitive env-var names accessed in client components
  for (const node of walkNodes(tree.rootNode)) {
    if (!stringTypes.includes(node.type)) continue;
    const value = extractStringValue(node);
    if (!ADMIN_VAR_PATTERNS.some(rx => rx.test(value))) continue;

    // Look for process.env['SERVICE_ROLE_KEY'] or process.env.SERVICE_ROLE_KEY patterns
    const parent = node.parent;
    const grandParent = parent?.parent;
    const isMemberAccess =
      parent?.type === 'subscript_expression' ||
      parent?.type === 'member_expression' ||
      grandParent?.type === 'member_expression';

    if (!isMemberAccess) continue;
    if (serverSide) continue;

    findings.push({
      rule: 'check_agent_permissions',
      severity: 'P0',
      message: `Environment variable "${value}" with admin/service-role semantics accessed in a client-side file. This key will be bundled and exposed.`,
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
      confidence: 95,
      snippet: node.text,
      fix_suggestion:
        `Move this access to a server-side API route or server action. Client components must never reference service-role or admin credentials.`,
    });
  }

  return findings;
}
