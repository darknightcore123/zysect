#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { runScan } from './scanner/index';

const ScanInput = z.object({
  file_path: z.string().describe('Path to the file being scanned (used for language detection and context)'),
  file_content: z.string().describe('Complete source code of the file'),
});

const TOOL_INPUT_SCHEMA = {
  type: 'object' as const,
  properties: {
    file_path: {
      type: 'string',
      description: 'Path to the file being scanned (used for language detection and context)',
    },
    file_content: {
      type: 'string',
      description: 'Complete source code of the file',
    },
  },
  required: ['file_path', 'file_content'],
};

const server = new Server(
  { name: 'zysect', version: '0.1.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'scan_file',
      description:
        'Run all Zysect security checks on a file. Use this as the default after generating any non-trivial code. Returns findings above the 95% confidence threshold only.',
      inputSchema: TOOL_INPUT_SCHEMA,
    },
    {
      name: 'check_api_keys',
      description:
        'Scan source code for hardcoded API keys, secrets, and tokens using AST traversal. Call when generating code containing string literals, especially in files that interact with external services.',
      inputSchema: TOOL_INPUT_SCHEMA,
    },
    {
      name: 'check_rate_limiting',
      description:
        'Detect missing rate limiters on authentication and sensitive endpoints. Call when generating Express/Hono route handlers or Next.js API routes for login, signup, or password reset.',
      inputSchema: TOOL_INPUT_SCHEMA,
    },
    {
      name: 'check_rls_config',
      description:
        'Detect insecure Supabase RLS configurations and missing row-ownership filters. Call when generating Supabase queries or any database access code.',
      inputSchema: TOOL_INPUT_SCHEMA,
    },
    {
      name: 'check_auth_middleware',
      description:
        'Find Next.js server actions and API route handlers that lack authentication guards. Call when generating server-side route handlers or files with the "use server" directive.',
      inputSchema: TOOL_INPUT_SCHEMA,
    },
    {
      name: 'check_sql_injection',
      description:
        'Detect SQL injection vulnerabilities from unsafe string interpolation or concatenation in database queries. Call when generating any code that constructs database query strings.',
      inputSchema: TOOL_INPUT_SCHEMA,
    },
    {
      name: 'check_input_limits',
      description:
        'Identify Express/Hono middleware and file upload handlers missing request body size limits. Call when generating Express app setup or file upload route handlers.',
      inputSchema: TOOL_INPUT_SCHEMA,
    },
    {
      name: 'check_agent_permissions',
      description:
        'Flag overly broad IAM wildcards and admin SDK/service account misuse. Call when generating IAM policies, Supabase client initialization, or Firebase admin code.',
      inputSchema: TOOL_INPUT_SCHEMA,
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: rawArgs } = request.params;

  const parsed = ScanInput.safeParse(rawArgs);
  if (!parsed.success) {
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            error: 'Invalid input',
            details: parsed.error.flatten(),
          }),
        },
      ],
      isError: true,
    };
  }

  const { file_path, file_content } = parsed.data;

  // Derive which rule to run (or all for scan_file)
  const rule = name === 'scan_file' ? undefined : name;

  const result = runScan({ filePath: file_path, fileContent: file_content, rule });

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(result, null, 2),
      },
    ],
  };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error('Zysect MCP server error:', err);
  process.exit(1);
});
