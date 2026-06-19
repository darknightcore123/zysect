# Zysect

**AST-based security scanner for AI-generated code.** Runs as a local MCP server inside Cursor, Windsurf, or any MCP-compatible IDE. No network calls. No false-positive noise below 95% confidence.

## What it catches

| Check | What it finds |
|---|---|
| `check_api_keys` | Hardcoded secrets — OpenAI, Anthropic, AWS, Stripe, GitHub, and 10 more providers |
| `check_rate_limiting` | Auth routes (login, signup, reset) without a rate limiter |
| `check_rls_config` | Supabase writes without user-ownership filters; service_role key in client code |
| `check_auth_middleware` | Next.js server actions and route handlers with no auth check |
| `check_sql_injection` | Template literals and string concatenation passed to raw query methods |
| `check_input_limits` | Express / multer middleware missing body size limits |
| `check_agent_permissions` | IAM wildcard `"*"` policies; admin SDK used outside server files |

All checks use tree-sitter AST traversal, not regex. A finding is only surfaced when confidence ≥ 95%.

## Install

```bash
npm install -g zysect-client
```

Or run directly without installing:

```bash
npx zysect-client
```

## Wire into Cursor

Add to your project's `.cursor/mcp.json` (or your global Cursor MCP config at `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "zysect": {
      "command": "zysect",
      "args": []
    }
  }
}
```

Restart Cursor. The `scan_file` tool will appear in your agent's tool list.

## Wire into Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "zysect": {
      "command": "zysect",
      "args": []
    }
  }
}
```

## Wire into Claude Code

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "zysect": {
      "command": "zysect",
      "args": []
    }
  }
}
```

## Usage from the agent

```
zysect.scan_file({
  file_path: "src/app/api/auth/login/route.ts",
  file_content: "<source code>"
})
```

Or call individual checks:

```
zysect.check_api_keys({ file_path: "...", file_content: "..." })
zysect.check_rls_config({ file_path: "...", file_content: "..." })
```

## Automatic scanning with .cursorrules

Drop a `.cursorrules` file in your project (see the one in this repo for a ready-made template) to instruct your AI agent to call `scan_file` automatically after generating code that touches auth, databases, uploads, or external APIs.

## Why not a linter or GitHub Action?

- **Linters** (ESLint, Semgrep) run after you commit. Zysect runs during generation, before the code lands.
- **GitHub Actions** run in the cloud after a push. Zysect is local — no data leaves your machine.
- **Regex scanners** generate noise. Zysect uses AST context to understand whether a string is actually a secret, whether a route is actually an auth endpoint, and whether a query call is actually database access.

## Validated against

Phase 1 gate: 492 source files across 4 real-world vibe-coded repos — zero false positives at the 95% confidence threshold.

## License

MIT
