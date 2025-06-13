# MCP Server Setup Template

This document provides a template for setting up a Model Context Protocol (MCP) server for any tool or service. We'll use Microsoft OneDrive as an example, but the same principles apply to any service that can be wrapped with MCP.

## Table of Contents
1. [Project Structure](#project-structure)
2. [Dependencies Setup](#dependencies-setup)
3. [Git Configuration](#git-configuration)
4. [Authentication Setup](#authentication-setup)
5. [Server Setup](#server-setup)
6. [Tool Implementation](#tool-implementation)
7. [Running the Server](#running-the-server)

## Project Structure

Create a new directory for your MCP server with the following structure:

```
your-mcp-server/
├── src/
│   ├── index.ts
│   ├── utl.ts
│   └── [service]-manager.ts
├── package.json
├── tsconfig.json
└── README.md
```

## Dependencies Setup

Create a `package.json` file with the following dependencies:

```json
{
  "name": "your-mcp-server",
  "version": "1.0.0",
  "description": "MCP HTTP server with Express and per-request authentication support",
  "type": "module",
  "main": "dist/index.js",
  "bin": {
    "your-mcp": "./dist/index.js"
  },
  "scripts": {
    "build": "tsc",
    "start": "node dist/index.js",
    "dev": "tsx src/index.ts",
    "dev:watch": "tsx watch src/index.ts",
    "prepare": "npm run build",
    "prepublishOnly": "npm run build"
  },
  "files": [
    "dist",
    "README.md"
  ],
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.12.0",
    "@types/express": "^5.0.2",
    "express": "^5.1.0",
    "zod": "^3.22.4",
    "zod-to-json-schema": "^3.22.1",
    "[service]-api-client": "latest"  // Replace with your service's API client
  },
  "devDependencies": {
    "@types/node": "^20.10.5",
    "tsx": "^4.19.4",
    "typescript": "^5.3.3"
  }
}
```

Create a `tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ES2020",
    "moduleResolution": "node",
    "esModuleInterop": true,
    "strict": true,
    "outDir": "./dist",
    "rootDir": "./src"
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules"]
}
```

## Git Configuration

Create a `.gitignore` file to exclude unnecessary files from version control:

```gitignore
# Dependencies
node_modules/
package-lock.json
yarn.lock

# Build output
dist/
build/

# Environment variables
.env
.env.local
.env.*.local

# IDE and editor files
.idea/
.vscode/
*.swp
*.swo
.DS_Store

# Logs
logs/
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# TypeScript
*.tsbuildinfo

# Testing
coverage/

# Temporary files
tmp/
temp/
```

This `.gitignore` file:
- Excludes dependency directories and lock files
- Ignores build output directories
- Protects sensitive environment variables
- Excludes IDE and editor-specific files
- Ignores log files
- Excludes TypeScript build info
- Ignores test coverage reports
- Excludes temporary files

## Authentication Setup

### 1. Identify OAuth Provider

First, identify the OAuth provider for your service. For example:
- Microsoft OneDrive: Microsoft Identity Platform
- Google Services: Google OAuth 2.0
- Dropbox: Dropbox OAuth 2.0

### 2. OAuth Configuration

Create the OAuth metadata configuration in your `index.ts`:

```typescript
// Example for Microsoft OneDrive
const microsoftOAuthMetadata = {
  issuer: "https://login.microsoftonline.com/common/v2.0",
  authorization_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
  token_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
  userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo",
  revocation_endpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/logout",
  jwks_uri: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: [
    "openid",
    "profile",
    "email",
    "offline_access",
    "Files.ReadWrite",
    "Files.ReadWrite.All"
  ],
  token_endpoint_auth_methods_supported: [
    "client_secret_basic",
    "client_secret_post"
  ],
  claims_supported: [
    "aud",
    "iss",
    "iat",
    "exp",
    "name",
    "oid",
    "preferred_username",
    "sub"
  ],
  code_challenge_methods_supported: ["S256"],
  grant_types_supported: ["authorization_code", "refresh_token"]
};
```

## Server Setup

### 1. Express Server Configuration

Set up your Express server with MCP integration:

```typescript
import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { mcpAuthMetadataRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";

const app = express();
app.use(express.json());

const SERVER_PORT = process.env.PORT || 3010;
const SERVER_HOST = process.env.SERVER_HOST || "localhost";

// Set up OAuth metadata routes
const resourceServerUrl = new URL(`http://${SERVER_HOST}:${SERVER_PORT}`);
app.use(
  mcpAuthMetadataRouter({
    oauthMetadata: microsoftOAuthMetadata, // Your service's OAuth metadata
    resourceServerUrl,
    scopesSupported: [
      "Files.ReadWrite",
      "Files.ReadWrite.All"
    ],
    resourceName: "OneDrive MCP Server",
  })
);

// Token verification middleware
const tokenMiddleware = requireBearerAuth({
  requiredScopes: ["Files.ReadWrite"],
  verifier: {
    verifyAccessToken: async (token: string): Promise<AuthInfo> => {
      // Implement token verification for your service
      // Example for Microsoft:
      const response = await fetch(
        `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration`
      );
      
      if (!response.ok) {
        throw new InvalidTokenError("Invalid token");
      }

      const tokenInfo = await response.json();
      
      return {
        token,
        clientId: tokenInfo.client_id || "microsoft",
        scopes: tokenInfo.scope ? tokenInfo.scope.split(" ") : ["files"],
        expiresAt: tokenInfo.exp ? parseInt(tokenInfo.exp) : undefined,
      };
    },
  },
});
```

### 2. MCP Endpoint Setup

```typescript
app.post("/mcp", tokenMiddleware, async (req: Request, res: Response) => {
  try {
    const server = getServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    
    res.on("close", () => {
      transport.close();
      server.close();
    });
    
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("Error handling MCP request:", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Internal server error",
        },
        id: null,
      });
    }
  }
});
```

## Tool Implementation

### 1. Define Tool Schemas

Create Zod schemas for your service's operations:

```typescript
import { z } from "zod";

// Example for OneDrive file operations
const ListFilesSchema = z.object({
  path: z.string().optional().describe("Path to list files from"),
  maxResults: z.number().optional().describe("Maximum number of results to return"),
});

const UploadFileSchema = z.object({
  path: z.string().describe("Path where to upload the file"),
  content: z.string().describe("File content in base64 format"),
  filename: z.string().describe("Name of the file"),
});

const DownloadFileSchema = z.object({
  fileId: z.string().describe("ID of the file to download"),
});
```

### 2. Implement Tool Handlers

```typescript
function getServer(): Server {
  const server = new Server(
    {
      name: "onedrive",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "list_files",
        description: "Lists files in a OneDrive folder",
        inputSchema: zodToJsonSchema(ListFilesSchema),
      },
      {
        name: "upload_file",
        description: "Uploads a file to OneDrive",
        inputSchema: zodToJsonSchema(UploadFileSchema),
      },
      {
        name: "download_file",
        description: "Downloads a file from OneDrive",
        inputSchema: zodToJsonSchema(DownloadFileSchema),
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request, { authInfo }) => {
    const { name, arguments: args } = request.params;
    
    // Create service client from authInfo
    const client = createServiceClient(authInfo);
    
    try {
      switch (name) {
        case "list_files": {
          const validatedArgs = ListFilesSchema.parse(args);
          // Implement file listing logic
          break;
        }
        case "upload_file": {
          const validatedArgs = UploadFileSchema.parse(args);
          // Implement file upload logic
          break;
        }
        case "download_file": {
          const validatedArgs = DownloadFileSchema.parse(args);
          // Implement file download logic
          break;
        }
        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } catch (error: any) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error.message}`,
          },
        ],
      };
    }
  });

  return server;
}
```

## Running the Server

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

The server will start and display:
- The server port
- OAuth metadata endpoints
- Authorization and token endpoints
- Required environment variables

## Environment Variables

Configure these environment variables:
- `PORT`: Server port (default: 3010)
- `SERVER_HOST`: Server hostname (default: localhost)

## Notes

1. The MCP client will:
   - Discover metadata from your server
   - Be directed to the appropriate OAuth servers for authentication
   - Send access tokens to your server for API calls

2. OAuth client credentials should be configured in the MCP client, not in this server.

3. Always implement proper error handling and token validation for your specific service.

4. Consider implementing rate limiting and other security measures based on your service's requirements.

5. Add appropriate logging and monitoring for production deployments. 