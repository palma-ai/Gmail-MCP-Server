#!/usr/bin/env node

import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { mcpAuthMetadataRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { google } from "googleapis";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { OAuth2Client } from "google-auth-library";
import { createEmailMessage } from "./utl.js";
import {
  createLabel,
  updateLabel,
  deleteLabel,
  listLabels,
  findLabelByName,
  getOrCreateLabel,
  GmailLabel,
} from "./label-manager.js";
import { Request, Response } from "express";

// Type definitions for Gmail API responses
interface GmailMessagePart {
  partId?: string;
  mimeType?: string;
  filename?: string;
  headers?: Array<{
    name: string;
    value: string;
  }>;
  body?: {
    attachmentId?: string;
    size?: number;
    data?: string;
  };
  parts?: GmailMessagePart[];
}

interface EmailAttachment {
  id: string;
  filename: string;
  mimeType: string;
  size: number;
}

interface EmailContent {
  text: string;
  html: string;
}

/**
 * Create Gmail client from authInfo
 */
function createGmailClient(authInfo: AuthInfo) {
  const oauth2Client = new OAuth2Client();
  oauth2Client.setCredentials({
    access_token: authInfo.token,
    expiry_date: authInfo.expiresAt ? authInfo.expiresAt * 1000 : undefined,
  });

  return google.gmail({ version: "v1", auth: oauth2Client });
}

/**
 * Recursively extract email body content from MIME message parts
 * Handles complex email structures with nested parts
 */
function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
  // Initialize containers for different content types
  let textContent = "";
  let htmlContent = "";

  // If the part has a body with data, process it based on MIME type
  if (messagePart.body && messagePart.body.data) {
    const content = Buffer.from(messagePart.body.data, "base64").toString(
      "utf8"
    );

    // Store content based on its MIME type
    if (messagePart.mimeType === "text/plain") {
      textContent = content;
    } else if (messagePart.mimeType === "text/html") {
      htmlContent = content;
    }
  }

  // If the part has nested parts, recursively process them
  if (messagePart.parts && messagePart.parts.length > 0) {
    for (const part of messagePart.parts) {
      const { text, html } = extractEmailContent(part);
      if (text) textContent += text;
      if (html) htmlContent += html;
    }
  }

  // Return both plain text and HTML content
  return { text: textContent, html: htmlContent };
}

// Schema definitions
const SendEmailSchema = z.object({
  to: z.array(z.string()).describe("List of recipient email addresses"),
  subject: z.string().describe("Email subject"),
  body: z
    .string()
    .describe(
      "Email body content (used for text/plain or when htmlBody not provided)"
    ),
  htmlBody: z.string().optional().describe("HTML version of the email body"),
  mimeType: z
    .enum(["text/plain", "text/html", "multipart/alternative"])
    .optional()
    .default("text/plain")
    .describe("Email content type"),
  cc: z.array(z.string()).optional().describe("List of CC recipients"),
  bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
  threadId: z.string().optional().describe("Thread ID to reply to"),
  inReplyTo: z.string().optional().describe("Message ID being replied to"),
});

const ReadEmailSchema = z.object({
  messageId: z.string().describe("ID of the email message to retrieve"),
});

const SearchEmailsSchema = z.object({
  query: z
    .string()
    .describe("Gmail search query (e.g., 'from:example@gmail.com')"),
  maxResults: z
    .number()
    .optional()
    .describe("Maximum number of results to return"),
});

// Updated schema to include removeLabelIds
const ModifyEmailSchema = z.object({
  messageId: z.string().describe("ID of the email message to modify"),
  labelIds: z
    .array(z.string())
    .optional()
    .describe("List of label IDs to apply"),
  addLabelIds: z
    .array(z.string())
    .optional()
    .describe("List of label IDs to add to the message"),
  removeLabelIds: z
    .array(z.string())
    .optional()
    .describe("List of label IDs to remove from the message"),
});

const DeleteEmailSchema = z.object({
  messageId: z.string().describe("ID of the email message to delete"),
});

// New schema for listing email labels
const ListEmailLabelsSchema = z
  .object({})
  .describe("Retrieves all available Gmail labels");

// Label management schemas
const CreateLabelSchema = z
  .object({
    name: z.string().describe("Name for the new label"),
    messageListVisibility: z
      .enum(["show", "hide"])
      .optional()
      .describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z
      .enum(["labelShow", "labelShowIfUnread", "labelHide"])
      .optional()
      .describe("Visibility of the label in the label list"),
  })
  .describe("Creates a new Gmail label");

const UpdateLabelSchema = z
  .object({
    id: z.string().describe("ID of the label to update"),
    name: z.string().optional().describe("New name for the label"),
    messageListVisibility: z
      .enum(["show", "hide"])
      .optional()
      .describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z
      .enum(["labelShow", "labelShowIfUnread", "labelHide"])
      .optional()
      .describe("Visibility of the label in the label list"),
  })
  .describe("Updates an existing Gmail label");

const DeleteLabelSchema = z
  .object({
    id: z.string().describe("ID of the label to delete"),
  })
  .describe("Deletes a Gmail label");

const GetOrCreateLabelSchema = z
  .object({
    name: z.string().describe("Name of the label to get or create"),
    messageListVisibility: z
      .enum(["show", "hide"])
      .optional()
      .describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z
      .enum(["labelShow", "labelShowIfUnread", "labelHide"])
      .optional()
      .describe("Visibility of the label in the label list"),
  })
  .describe("Gets an existing label by name or creates it if it doesn't exist");

// Schemas for batch operations
const BatchModifyEmailsSchema = z.object({
  messageIds: z.array(z.string()).describe("List of message IDs to modify"),
  addLabelIds: z
    .array(z.string())
    .optional()
    .describe("List of label IDs to add to all messages"),
  removeLabelIds: z
    .array(z.string())
    .optional()
    .describe("List of label IDs to remove from all messages"),
  batchSize: z
    .number()
    .optional()
    .default(50)
    .describe("Number of messages to process in each batch (default: 50)"),
});

const BatchDeleteEmailsSchema = z.object({
  messageIds: z.array(z.string()).describe("List of message IDs to delete"),
  batchSize: z
    .number()
    .optional()
    .default(50)
    .describe("Number of messages to process in each batch (default: 50)"),
});

// Server factory function
function getServer(): Server {
  const server = new Server(
    {
      name: "gmail",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Tool handlers
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "send_email",
        description: "Sends a new email",
        inputSchema: zodToJsonSchema(SendEmailSchema),
      },
      {
        name: "draft_email",
        description: "Draft a new email",
        inputSchema: zodToJsonSchema(SendEmailSchema),
      },
      {
        name: "read_email",
        description: "Retrieves the content of a specific email",
        inputSchema: zodToJsonSchema(ReadEmailSchema),
      },
      {
        name: "search_emails",
        description: "Searches for emails using Gmail search syntax",
        inputSchema: zodToJsonSchema(SearchEmailsSchema),
      },
      {
        name: "modify_email",
        description: "Modifies email labels (move to different folders)",
        inputSchema: zodToJsonSchema(ModifyEmailSchema),
      },
      {
        name: "delete_email",
        description: "Permanently deletes an email",
        inputSchema: zodToJsonSchema(DeleteEmailSchema),
      },
      {
        name: "list_email_labels",
        description: "Retrieves all available Gmail labels",
        inputSchema: zodToJsonSchema(ListEmailLabelsSchema),
      },
      {
        name: "batch_modify_emails",
        description: "Modifies labels for multiple emails in batches",
        inputSchema: zodToJsonSchema(BatchModifyEmailsSchema),
      },
      {
        name: "batch_delete_emails",
        description: "Permanently deletes multiple emails in batches",
        inputSchema: zodToJsonSchema(BatchDeleteEmailsSchema),
      },
      {
        name: "create_label",
        description: "Creates a new Gmail label",
        inputSchema: zodToJsonSchema(CreateLabelSchema),
      },
      {
        name: "update_label",
        description: "Updates an existing Gmail label",
        inputSchema: zodToJsonSchema(UpdateLabelSchema),
      },
      {
        name: "delete_label",
        description: "Deletes a Gmail label",
        inputSchema: zodToJsonSchema(DeleteLabelSchema),
      },
      {
        name: "get_or_create_label",
        description:
          "Gets an existing label by name or creates it if it doesn't exist",
        inputSchema: zodToJsonSchema(GetOrCreateLabelSchema),
      },
    ],
  }));

  server.setRequestHandler(
    CallToolRequestSchema,
    async (request, { authInfo }) => {
      console.log(authInfo);
      const { name, arguments: args } = request.params;

      // Create Gmail client from authInfo for this request
      if (!authInfo) {
        return {
          content: [
            {
              type: "text",
              text: "Error: Authentication required. Please provide valid authInfo.",
            },
          ],
        };
      }

      const gmail = createGmailClient(authInfo);

      async function handleEmailAction(
        action: "send" | "draft",
        validatedArgs: any
      ) {
        const message = createEmailMessage(validatedArgs);

        const encodedMessage = Buffer.from(message)
          .toString("base64")
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=+$/, "");

        // Define the type for messageRequest
        interface GmailMessageRequest {
          raw: string;
          threadId?: string;
        }

        const messageRequest: GmailMessageRequest = {
          raw: encodedMessage,
        };

        // Add threadId if specified
        if (validatedArgs.threadId) {
          messageRequest.threadId = validatedArgs.threadId;
        }

        if (action === "send") {
          const response = await gmail.users.messages.send({
            userId: "me",
            requestBody: messageRequest,
          });
          return {
            content: [
              {
                type: "text",
                text: `Email sent successfully with ID: ${response.data.id}`,
              },
            ],
          };
        } else {
          const response = await gmail.users.drafts.create({
            userId: "me",
            requestBody: {
              message: messageRequest,
            },
          });
          return {
            content: [
              {
                type: "text",
                text: `Email draft created successfully with ID: ${response.data.id}`,
              },
            ],
          };
        }
      }

      // Helper function to process operations in batches
      async function processBatches<T, U>(
        items: T[],
        batchSize: number,
        processFn: (batch: T[]) => Promise<U[]>
      ): Promise<{ successes: U[]; failures: { item: T; error: Error }[] }> {
        const successes: U[] = [];
        const failures: { item: T; error: Error }[] = [];

        // Process in batches
        for (let i = 0; i < items.length; i += batchSize) {
          const batch = items.slice(i, i + batchSize);
          try {
            const results = await processFn(batch);
            successes.push(...results);
          } catch (error) {
            // If batch fails, try individual items
            for (const item of batch) {
              try {
                const result = await processFn([item]);
                successes.push(...result);
              } catch (itemError) {
                failures.push({ item, error: itemError as Error });
              }
            }
          }
        }

        return { successes, failures };
      }

      try {
        switch (name) {
          case "send_email":
          case "draft_email": {
            const validatedArgs = SendEmailSchema.parse(args);
            const action = name === "send_email" ? "send" : "draft";
            return await handleEmailAction(action, validatedArgs);
          }

          case "read_email": {
            const validatedArgs = ReadEmailSchema.parse(args);
            const response = await gmail.users.messages.get({
              userId: "me",
              id: validatedArgs.messageId,
              format: "full",
            });

            const headers = response.data.payload?.headers || [];
            const subject =
              headers.find((h: any) => h.name?.toLowerCase() === "subject")
                ?.value || "";
            const from =
              headers.find((h: any) => h.name?.toLowerCase() === "from")
                ?.value || "";
            const to =
              headers.find((h: any) => h.name?.toLowerCase() === "to")?.value ||
              "";
            const date =
              headers.find((h: any) => h.name?.toLowerCase() === "date")
                ?.value || "";
            const threadId = response.data.threadId || "";

            // Extract email content using the recursive function
            const { text, html } = extractEmailContent(
              (response.data.payload as GmailMessagePart) || {}
            );

            // Use plain text content if available, otherwise use HTML content
            // (optionally, you could implement HTML-to-text conversion here)
            let body = text || html || "";

            // If we only have HTML content, add a note for the user
            const contentTypeNote =
              !text && html
                ? "[Note: This email is HTML-formatted. Plain text version not available.]\n\n"
                : "";

            // Get attachment information
            const attachments: EmailAttachment[] = [];
            const processAttachmentParts = (
              part: GmailMessagePart,
              path: string = ""
            ) => {
              if (part.body && part.body.attachmentId) {
                const filename =
                  part.filename || `attachment-${part.body.attachmentId}`;
                attachments.push({
                  id: part.body.attachmentId,
                  filename: filename,
                  mimeType: part.mimeType || "application/octet-stream",
                  size: part.body.size || 0,
                });
              }

              if (part.parts) {
                part.parts.forEach((subpart: GmailMessagePart) =>
                  processAttachmentParts(subpart, `${path}/parts`)
                );
              }
            };

            if (response.data.payload) {
              processAttachmentParts(response.data.payload as GmailMessagePart);
            }

            // Add attachment info to output if any are present
            const attachmentInfo =
              attachments.length > 0
                ? `\n\nAttachments (${attachments.length}):\n` +
                  attachments
                    .map(
                      (a) =>
                        `- ${a.filename} (${a.mimeType}, ${Math.round(
                          a.size / 1024
                        )} KB)`
                    )
                    .join("\n")
                : "";

            return {
              content: [
                {
                  type: "text",
                  text: `Thread ID: ${threadId}\nSubject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}${attachmentInfo}`,
                },
              ],
            };
          }

          case "search_emails": {
            const validatedArgs = SearchEmailsSchema.parse(args);
            const response = await gmail.users.messages.list({
              userId: "me",
              q: validatedArgs.query,
              maxResults: validatedArgs.maxResults || 10,
            });

            const messages = response.data.messages || [];
            const results = await Promise.all(
              messages.map(async (msg: any) => {
                const detail = await gmail.users.messages.get({
                  userId: "me",
                  id: msg.id!,
                  format: "metadata",
                  metadataHeaders: ["Subject", "From", "Date"],
                });
                const headers = detail.data.payload?.headers || [];
                return {
                  id: msg.id,
                  subject:
                    headers.find((h: any) => h.name === "Subject")?.value || "",
                  from:
                    headers.find((h: any) => h.name === "From")?.value || "",
                  date:
                    headers.find((h: any) => h.name === "Date")?.value || "",
                };
              })
            );

            return {
              content: [
                {
                  type: "text",
                  text: results
                    .map(
                      (r: any) =>
                        `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}\n`
                    )
                    .join("\n"),
                },
              ],
            };
          }

          // Updated implementation for the modify_email handler
          case "modify_email": {
            const validatedArgs = ModifyEmailSchema.parse(args);

            // Prepare request body
            const requestBody: any = {};

            if (validatedArgs.labelIds) {
              requestBody.addLabelIds = validatedArgs.labelIds;
            }

            if (validatedArgs.addLabelIds) {
              requestBody.addLabelIds = validatedArgs.addLabelIds;
            }

            if (validatedArgs.removeLabelIds) {
              requestBody.removeLabelIds = validatedArgs.removeLabelIds;
            }

            await gmail.users.messages.modify({
              userId: "me",
              id: validatedArgs.messageId,
              requestBody: requestBody,
            });

            return {
              content: [
                {
                  type: "text",
                  text: `Email ${validatedArgs.messageId} labels updated successfully`,
                },
              ],
            };
          }

          case "delete_email": {
            const validatedArgs = DeleteEmailSchema.parse(args);
            await gmail.users.messages.delete({
              userId: "me",
              id: validatedArgs.messageId,
            });

            return {
              content: [
                {
                  type: "text",
                  text: `Email ${validatedArgs.messageId} deleted successfully`,
                },
              ],
            };
          }

          case "list_email_labels": {
            const labelResults = await listLabels(gmail);
            const systemLabels = labelResults.system;
            const userLabels = labelResults.user;

            return {
              content: [
                {
                  type: "text",
                  text:
                    `Found ${labelResults.count.total} labels (${labelResults.count.system} system, ${labelResults.count.user} user):\n\n` +
                    "System Labels:\n" +
                    systemLabels
                      .map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`)
                      .join("\n") +
                    "\nUser Labels:\n" +
                    userLabels
                      .map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`)
                      .join("\n"),
                },
              ],
            };
          }

          case "batch_modify_emails": {
            const validatedArgs = BatchModifyEmailsSchema.parse(args);
            const messageIds = validatedArgs.messageIds;
            const batchSize = validatedArgs.batchSize || 50;

            // Prepare request body
            const requestBody: any = {};

            if (validatedArgs.addLabelIds) {
              requestBody.addLabelIds = validatedArgs.addLabelIds;
            }

            if (validatedArgs.removeLabelIds) {
              requestBody.removeLabelIds = validatedArgs.removeLabelIds;
            }

            // Process messages in batches
            const { successes, failures } = await processBatches(
              messageIds,
              batchSize,
              async (batch) => {
                const results = await Promise.all(
                  batch.map(async (messageId) => {
                    const result = await gmail.users.messages.modify({
                      userId: "me",
                      id: messageId,
                      requestBody: requestBody,
                    });
                    return { messageId, success: true };
                  })
                );
                return results;
              }
            );

            // Generate summary of the operation
            const successCount = successes.length;
            const failureCount = failures.length;

            let resultText = `Batch label modification complete.\n`;
            resultText += `Successfully processed: ${successCount} messages\n`;

            if (failureCount > 0) {
              resultText += `Failed to process: ${failureCount} messages\n\n`;
              resultText += `Failed message IDs:\n`;
              resultText += failures
                .map(
                  (f) =>
                    `- ${(f.item as string).substring(0, 16)}... (${
                      f.error.message
                    })`
                )
                .join("\n");
            }

            return {
              content: [
                {
                  type: "text",
                  text: resultText,
                },
              ],
            };
          }

          case "batch_delete_emails": {
            const validatedArgs = BatchDeleteEmailsSchema.parse(args);
            const messageIds = validatedArgs.messageIds;
            const batchSize = validatedArgs.batchSize || 50;

            // Process messages in batches
            const { successes, failures } = await processBatches(
              messageIds,
              batchSize,
              async (batch) => {
                const results = await Promise.all(
                  batch.map(async (messageId) => {
                    await gmail.users.messages.delete({
                      userId: "me",
                      id: messageId,
                    });
                    return { messageId, success: true };
                  })
                );
                return results;
              }
            );

            // Generate summary of the operation
            const successCount = successes.length;
            const failureCount = failures.length;

            let resultText = `Batch delete operation complete.\n`;
            resultText += `Successfully deleted: ${successCount} messages\n`;

            if (failureCount > 0) {
              resultText += `Failed to delete: ${failureCount} messages\n\n`;
              resultText += `Failed message IDs:\n`;
              resultText += failures
                .map(
                  (f) =>
                    `- ${(f.item as string).substring(0, 16)}... (${
                      f.error.message
                    })`
                )
                .join("\n");
            }

            return {
              content: [
                {
                  type: "text",
                  text: resultText,
                },
              ],
            };
          }

          // New label management handlers
          case "create_label": {
            const validatedArgs = CreateLabelSchema.parse(args);
            const result = await createLabel(gmail, validatedArgs.name, {
              messageListVisibility: validatedArgs.messageListVisibility,
              labelListVisibility: validatedArgs.labelListVisibility,
            });

            return {
              content: [
                {
                  type: "text",
                  text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                },
              ],
            };
          }

          case "update_label": {
            const validatedArgs = UpdateLabelSchema.parse(args);

            // Prepare request body with only the fields that were provided
            const updates: any = {};
            if (validatedArgs.name) updates.name = validatedArgs.name;
            if (validatedArgs.messageListVisibility)
              updates.messageListVisibility =
                validatedArgs.messageListVisibility;
            if (validatedArgs.labelListVisibility)
              updates.labelListVisibility = validatedArgs.labelListVisibility;

            const result = await updateLabel(gmail, validatedArgs.id, updates);

            return {
              content: [
                {
                  type: "text",
                  text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                },
              ],
            };
          }

          case "delete_label": {
            const validatedArgs = DeleteLabelSchema.parse(args);
            const result = await deleteLabel(gmail, validatedArgs.id);

            return {
              content: [
                {
                  type: "text",
                  text: result.message,
                },
              ],
            };
          }

          case "get_or_create_label": {
            const validatedArgs = GetOrCreateLabelSchema.parse(args);
            const result = await getOrCreateLabel(gmail, validatedArgs.name, {
              messageListVisibility: validatedArgs.messageListVisibility,
              labelListVisibility: validatedArgs.labelListVisibility,
            });

            const action =
              result.type === "user" && result.name === validatedArgs.name
                ? "found existing"
                : "created new";

            return {
              content: [
                {
                  type: "text",
                  text: `Successfully ${action} label:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
                },
              ],
            };
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
    }
  );

  return server;
}

// Express server setup
const app = express();
app.use(express.json());

// Get server configuration from environment variables
const SERVER_PORT = process.env.PORT || 3010;
const SERVER_HOST = process.env.SERVER_HOST || "localhost";

// Google OAuth 2.0 endpoints and metadata
const googleOAuthMetadata = {
  issuer: "https://accounts.google.com",
  authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  token_endpoint: "https://oauth2.googleapis.com/token",
  userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
  revocation_endpoint: "https://oauth2.googleapis.com/revoke",
  jwks_uri: "https://www.googleapis.com/oauth2/v3/certs",
  response_types_supported: ["code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
  scopes_supported: [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/gmail.send",
  ],
  token_endpoint_auth_methods_supported: [
    "client_secret_basic",
    "client_secret_post",
  ],
  claims_supported: [
    "aud",
    "email",
    "email_verified",
    "exp",
    "family_name",
    "given_name",
    "iat",
    "iss",
    "locale",
    "name",
    "picture",
    "sub",
  ],
  code_challenge_methods_supported: ["S256"],
  grant_types_supported: ["authorization_code", "refresh_token"],
};

// Set up OAuth metadata routes - points clients to Google's OAuth servers
const resourceServerUrl = new URL(`http://${SERVER_HOST}:${SERVER_PORT}`);
app.use(
  mcpAuthMetadataRouter({
    oauthMetadata: googleOAuthMetadata,
    resourceServerUrl,
    scopesSupported: [
      "https://www.googleapis.com/auth/gmail.modify",
      "https://www.googleapis.com/auth/gmail.labels",
      "https://www.googleapis.com/auth/gmail.send",
    ],
    resourceName: "Gmail MCP Server",
  })
);

// Middleware to handle bearer token authentication with Google token verification
const tokenMiddleware = requireBearerAuth({
  requiredScopes: ["https://www.googleapis.com/auth/gmail.modify"],
  verifier: {
    verifyAccessToken: async (token: string): Promise<AuthInfo> => {
      console.log("Verifying token", token);
      // Use Google's tokeninfo endpoint to verify the token
      const response = await fetch(
        `https://oauth2.googleapis.com/tokeninfo?access_token=${token}`
      );

      // Important: IF not MCP client will not refresh tokens
      if (!response.ok && [400, 401].includes(response.status)) {
        throw new InvalidTokenError("Invalid token");
      }

      if (!response.ok) {
        throw new InvalidTokenError(
          `Token verification failed with status ${response.status}`
        );
      }

      const tokenInfo = await response.json();

      // Google's tokeninfo endpoint validates the token for us
      // No need to check client ID since we accept any valid Google token
      return {
        token,
        clientId: tokenInfo.aud || "google",
        scopes: tokenInfo.scope ? tokenInfo.scope.split(" ") : ["gmail"],
        expiresAt: tokenInfo.exp ? parseInt(tokenInfo.exp) : undefined,
      };
    },
  },
});

app.post("/mcp", tokenMiddleware, async (req: Request, res: Response) => {
  // In stateless mode, create a new instance of transport and server for each request
  // to ensure complete isolation. A single instance would cause request ID collisions
  // when multiple clients connect concurrently.

  try {
    console.log("Creating server");
    const server = getServer();
    console.log("Creating transport");
    const transport: StreamableHTTPServerTransport =
      new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
    res.on("close", () => {
      console.log("Request closed");
      transport.close();
      server.close();
    });
    console.log("Connecting to server");
    await server.connect(transport);
    console.log("Request received", req.body);
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

app.get("/mcp", async (req: Request, res: Response) => {
  console.log("Received GET MCP request");
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed.",
      },
      id: null,
    })
  );
});

app.delete("/mcp", async (req: Request, res: Response) => {
  console.log("Received DELETE MCP request");
  res.writeHead(405).end(
    JSON.stringify({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed.",
      },
      id: null,
    })
  );
});

// Start the server
app.listen(SERVER_PORT, () => {
  console.log(
    `Gmail MCP Stateless Streamable HTTP Server listening on port ${SERVER_PORT}`
  );
  console.log(
    `OAuth Protected Resource Metadata: ${resourceServerUrl.origin}/.well-known/oauth-protected-resource`
  );
  console.log(
    `OAuth Authorization Server Metadata: ${resourceServerUrl.origin}/.well-known/oauth-authorization-server`
  );
  console.log(
    `Google OAuth Authorization Endpoint: ${googleOAuthMetadata.authorization_endpoint}`
  );
  console.log(
    `Google OAuth Token Endpoint: ${googleOAuthMetadata.token_endpoint}`
  );
  console.log("");
  console.log("Optional environment variables:");
  console.log("- PORT: Server port (default: 3010)");
  console.log("- SERVER_HOST: Server hostname (default: localhost)");
  console.log("");
  console.log("The MCP client will:");
  console.log("1. Discover metadata from your server");
  console.log("2. Be directed to Google's OAuth servers for authentication");
  console.log("3. Send Google access tokens to your server for API calls");
  console.log("");
  console.log(
    "Note: Google OAuth client credentials are configured in the MCP client, not this server."
  );
});
