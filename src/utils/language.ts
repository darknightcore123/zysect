import path from 'path';
import { SupportedLanguage } from '../types';

export function detectLanguage(filePath: string): SupportedLanguage {
  const ext = path.extname(filePath).toLowerCase().slice(1);
  switch (ext) {
    case 'js':
    case 'mjs':
    case 'cjs':
    case 'jsx':
      return 'javascript';
    case 'ts':
      return 'typescript';
    case 'tsx':
      return 'tsx';
    case 'py':
      return 'python';
    case 'go':
      return 'go';
    case 'java':
      return 'java';
    case 'rb':
      return 'ruby';
    default:
      return 'unknown';
  }
}

// True for files that are likely server-side (affects some rule confidence).
export function isServerSideFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return (
    /\/api\//.test(normalized) ||
    /\/server\//.test(normalized) ||
    /\/actions\//.test(normalized) ||
    /\.server\.(ts|js|tsx)$/.test(normalized) ||
    /route\.(ts|js)$/.test(normalized)
  );
}

// True for test/mock files — reduces confidence for some checks.
export function isTestFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return (
    /\.(test|spec)\.(ts|js|tsx|js)$/.test(normalized) ||
    /__tests__\//.test(normalized) ||
    /\/tests?\//.test(normalized) ||
    /\/mocks\//.test(normalized) ||
    /\/fixtures\//.test(normalized)
  );
}

// True for migration scripts, seeders, cron jobs, admin scripts, and developer
// diagnostic scripts that intentionally run in a trusted context and bypass RLS.
export function isAdminOrMigrationScript(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  const fileName = normalized.split('/').pop() ?? '';
  return (
    /\/scripts\//.test(normalized) ||
    /\/migrations?\//.test(normalized) ||
    /\/seeders?\//.test(normalized) ||
    /\/seeds?\//.test(normalized) ||
    /\/cron\//.test(normalized) ||
    /\/jobs\//.test(normalized) ||
    /\/(seed|migrate|migration|admin|setup|bootstrap|init-db)\.(ts|js)$/.test(normalized) ||
    /\/prisma\//.test(normalized) ||
    /\/drizzle\//.test(normalized) ||
    // Test/diagnostic directories
    /\/tests?\//.test(normalized) ||
    /\/tools\//.test(normalized) ||
    /\/__tests__\//.test(normalized) ||
    // Root-level diagnostic scripts by naming convention (test-*, diagnose-*, fix-*, etc.)
    // Matches both "test-foo.js" and "comprehensive-test.js" (hyphen OR dot after the prefix)
    /^(test|diagnose|detect|fix|restore|debug)[-_.]/.test(fileName) ||
    /^comprehensive-test[-_.]/.test(fileName)
  );
}

// True for routes that are intentionally public by convention (webhooks, telemetry,
// health checks, OAuth callbacks). Auth middleware is not applicable to these.
export function isPubliclyIntendedRoute(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  return (
    // Matches /webhook/, /webhooks/, /support-webhook/, /lemonsqueezy-webhook/, etc.
    /\/[^/]*webhooks?[^/]*\//.test(normalized) ||
    /\/supabase\/functions\//.test(normalized) ||
    /\/metrics\//.test(normalized) ||
    /\/analytics\//.test(normalized) ||
    /\/health\b/.test(normalized) ||
    /\/healthz\//.test(normalized) ||
    /\/ping\//.test(normalized) ||
    /\/status\//.test(normalized) ||
    /\/public\//.test(normalized) ||
    /\/telemetry\//.test(normalized) ||
    /\/callback\//.test(normalized) ||
    /\/oauth\//.test(normalized)
  );
}

// True for routes that ARE the authentication mechanism — login, register, etc.
// These endpoints are intentionally unauthenticated by design.
export function isAuthEndpoint(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();
  return /\/auth\/(login|register|signup|signin|confirm|reset|forgot|verify|magic|otp|resend)/.test(normalized);
}
