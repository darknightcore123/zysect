import Parser from 'tree-sitter';
import { Finding, SupportedLanguage } from '../types';
import { walkNodes, getImportSources } from '../utils/ast';

// Body-parser middleware that accept an optional options object with `limit`.
const BODY_PARSER_FN_NAMES = new Set([
  'json',
  'urlencoded',
  'text',
  'raw',
]);

// Middleware factory names from popular packages.
const MIDDLEWARE_FACTORY_NAMES = new Set([
  'bodyParser',
  'express',
  'multer',
  'formidable',
  'busboy',
]);

// Returns true if the given options object node contains a `limit` key.
function optionsHasLimit(optionsNode: Parser.SyntaxNode): boolean {
  for (const child of walkNodes(optionsNode)) {
    if (
      (child.type === 'property_identifier' || child.type === 'shorthand_property_identifier') &&
      child.text === 'limit'
    ) {
      return true;
    }
    // object key as string
    if (child.type === 'string' && child.text.includes('limit')) return true;
  }
  return false;
}

export function checkInputLimits(
  tree: Parser.Tree,
  _code: string,
  language: SupportedLanguage,
): Finding[] {
  if (!['javascript', 'typescript', 'tsx'].includes(language)) return [];

  const findings: Finding[] = [];
  const imports = getImportSources(tree);

  const usesExpress = imports.some(
    s => s === 'express' || s === 'express-json',
  );
  const usesBodyParser = imports.some(s => s === 'body-parser');
  const usesMulter = imports.some(s => s === 'multer');

  if (!usesExpress && !usesBodyParser && !usesMulter) return [];

  for (const node of walkNodes(tree.rootNode)) {
    if (node.type !== 'call_expression') continue;

    const fn = node.childForFieldName('function');
    if (!fn) continue;

    // Match: express.json(), express.urlencoded(), bodyParser.json(), etc.
    if (fn.type === 'member_expression') {
      const obj = fn.childForFieldName('object');
      const prop = fn.childForFieldName('property');

      if (
        !obj ||
        !prop ||
        !MIDDLEWARE_FACTORY_NAMES.has(obj.text) ||
        !BODY_PARSER_FN_NAMES.has(prop.text)
      ) continue;

      const args = node.childForFieldName('arguments');
      const optionsArg = args?.namedChild(0);

      // No options passed at all → no limit
      if (!optionsArg) {
        findings.push({
          rule: 'check_input_limits',
          severity: 'P1',
          message: `\`${obj.text}.${prop.text}()\` called without a \`limit\` option. Default limit is 100kb; large payloads can exhaust memory.`,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          confidence: 95,
          snippet: node.text.slice(0, 100),
          fix_suggestion:
            `Set an explicit limit: \`${obj.text}.${prop.text}({ limit: "1mb" })\`. Choose the smallest value your use case actually needs.`,
        });
        continue;
      }

      if (optionsArg.type === 'object' && !optionsHasLimit(optionsArg)) {
        findings.push({
          rule: 'check_input_limits',
          severity: 'P1',
          message: `\`${obj.text}.${prop.text}()\` options object has no \`limit\` property.`,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          confidence: 95,
          snippet: node.text.slice(0, 100),
          fix_suggestion:
            `Add \`limit: "1mb"\` to the options: \`${obj.text}.${prop.text}({ ..., limit: "1mb" })\`.`,
        });
      }
    }

    // Match: multer() called without { limits: { fileSize: ... } }
    if (fn.type === 'identifier' && fn.text === 'multer' && usesMulter) {
      const args = node.childForFieldName('arguments');
      const optionsArg = args?.namedChild(0);

      if (!optionsArg) {
        findings.push({
          rule: 'check_input_limits',
          severity: 'P1',
          message: `\`multer()\` called without a \`limits\` option. Accepting unbounded file uploads enables denial-of-service attacks.`,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          confidence: 96,
          snippet: node.text.slice(0, 100),
          fix_suggestion:
            'Add file size and count limits: `multer({ limits: { fileSize: 5 * 1024 * 1024, files: 5 } })`.',
        });
      }
    }
  }

  return findings;
}
