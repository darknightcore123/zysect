import Parser from 'tree-sitter';
import { SupportedLanguage } from '../types';

// Lazily-loaded parser cache — one parser per language.
const parserCache = new Map<SupportedLanguage, Parser>();
const grammarLoadErrors = new Set<SupportedLanguage>();

function loadGrammar(language: SupportedLanguage): unknown | null {
  try {
    switch (language) {
      case 'javascript':
        return require('tree-sitter-javascript');
      case 'typescript':
        return (require('tree-sitter-typescript') as { typescript: unknown }).typescript;
      case 'tsx':
        return (require('tree-sitter-typescript') as { tsx: unknown }).tsx;
      case 'python':
        return require('tree-sitter-python');
      case 'go':
        return require('tree-sitter-go');
      case 'java':
        return require('tree-sitter-java');
      case 'ruby':
        return require('tree-sitter-ruby');
      default:
        return null;
    }
  } catch {
    return null;
  }
}

export function getParser(language: SupportedLanguage): Parser | null {
  if (grammarLoadErrors.has(language)) return null;
  if (parserCache.has(language)) return parserCache.get(language)!;

  const grammar = loadGrammar(language);
  if (!grammar) {
    grammarLoadErrors.add(language);
    return null;
  }

  try {
    const parser = new Parser();
    parser.setLanguage(grammar);
    parserCache.set(language, parser);
    return parser;
  } catch {
    grammarLoadErrors.add(language);
    return null;
  }
}

export function parseCode(code: string, language: SupportedLanguage): Parser.Tree | null {
  const parser = getParser(language);
  if (!parser) return null;
  try {
    return parser.parse(code);
  } catch {
    return null;
  }
}

// Depth-first generator over all nodes in a subtree.
export function* walkNodes(node: Parser.SyntaxNode): Generator<Parser.SyntaxNode> {
  yield node;
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) yield* walkNodes(child);
  }
}

// String node type names differ across grammars.
export function getStringNodeTypes(language: SupportedLanguage): string[] {
  switch (language) {
    case 'javascript':
    case 'typescript':
    case 'tsx':
      return ['string'];
    case 'python':
      return ['string'];
    case 'go':
      return ['interpreted_string_literal', 'raw_string_literal'];
    case 'java':
      return ['string_literal'];
    case 'ruby':
      return ['string_content', 'string'];
    default:
      return ['string'];
  }
}

// Strips surrounding quote characters from a string node's raw text.
export function extractStringValue(node: Parser.SyntaxNode): string {
  const text = node.text;

  // Python/JS triple-quoted strings
  if (text.startsWith('"""') && text.endsWith('"""')) return text.slice(3, -3);
  if (text.startsWith("'''") && text.endsWith("'''")) return text.slice(3, -3);

  // Standard single/double quoted
  if (text.length >= 2) {
    const first = text[0];
    const last = text[text.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return text.slice(1, -1);
    }
  }

  return text;
}

// Walk up the ancestor chain to find the variable/property name a value is
// assigned to. Returns the identifier text or null if no context is found.
export function getVariableContext(node: Parser.SyntaxNode): string | null {
  let current: Parser.SyntaxNode | null = node.parent;
  let depth = 0;

  while (current && depth < 6) {
    switch (current.type) {
      case 'variable_declarator': {
        const nameNode = current.childForFieldName('name');
        if (nameNode) return nameNode.text;
        break;
      }
      case 'pair':
      case 'property': {
        const keyNode = current.childForFieldName('key');
        if (keyNode) return keyNode.text.replace(/['"]/g, '');
        break;
      }
      case 'assignment_expression': {
        const leftNode = current.childForFieldName('left');
        if (leftNode) return leftNode.text;
        break;
      }
      case 'keyword_argument':  // Python
      case 'argument': {
        const nameNode = current.childForFieldName('name');
        if (nameNode) return nameNode.text;
        break;
      }
    }

    // Stop climbing at scope boundaries
    if (
      current.type === 'function_declaration' ||
      current.type === 'function_expression' ||
      current.type === 'arrow_function' ||
      current.type === 'class_body' ||
      current.type === 'module'
    ) {
      break;
    }

    current = current.parent;
    depth++;
  }

  return null;
}

// Return all import source strings found in a JS/TS file.
export function getImportSources(tree: Parser.Tree): string[] {
  const sources: string[] = [];
  for (const node of walkNodes(tree.rootNode)) {
    if (node.type === 'import_statement' || node.type === 'import_declaration') {
      const source = node.childForFieldName('source');
      if (source) sources.push(extractStringValue(source));
    }
    // CommonJS require()
    if (node.type === 'call_expression') {
      const fn = node.childForFieldName('function');
      if (fn?.text === 'require') {
        const args = node.childForFieldName('arguments');
        if (args) {
          const firstArg = args.namedChild(0);
          if (firstArg?.type === 'string') sources.push(extractStringValue(firstArg));
        }
      }
    }
  }
  return sources;
}
