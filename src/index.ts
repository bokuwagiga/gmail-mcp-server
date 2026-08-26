import express, { Request, Response } from "express";
import { rateLimit } from "express-rate-limit";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { google } from "googleapis";
import { z } from "zod";
import { GmailService } from "./gmail-service.js";
import { TokenStore } from "./token-store.js";
import {
  GmailMcpAuthProvider,
  SESSION_COOKIE,
  clearSessionCookie,
  escapeHtml,
  getAdminSession,
  readCookie,
  renderLoginPage,
  requireAdminSession,
  safeEqual,
  setSessionCookie,
} from "./auth.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    console.error(`Missing required environment variable: ${name}`);
    process.exit(1);
  }
  return value;
}

const PORT = parseInt(process.env.PORT || "3000", 10);
const SERVER_URL = (process.env.SERVER_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");
const MCP_URL = new URL("/mcp", SERVER_URL);
const GOOGLE_CLIENT_ID = requireEnv("GOOGLE_CLIENT_ID");
const GOOGLE_CLIENT_SECRET = requireEnv("GOOGLE_CLIENT_SECRET");
const ADMIN_PASSWORD = requireEnv("ADMIN_PASSWORD");
const ENCRYPTION_KEY = requireEnv("ENCRYPTION_KEY");
// Signs OAuth tokens / admin sessions. Falls back to ENCRYPTION_KEY so existing
// deployments need no new variable; set AUTH_SECRET to rotate tokens independently.
const AUTH_SECRET = process.env.AUTH_SECRET || ENCRYPTION_KEY;
// Hosts allowed to receive OAuth redirects (i.e. which MCP clients may connect).
const ALLOWED_REDIRECT_HOSTS = (process.env.ALLOWED_REDIRECT_HOSTS || "claude.ai,claude.com")
  .split(",")
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);
const TRUST_PROXY = process.env.TRUST_PROXY === "false" ? false : 1;
const SECURE_COOKIES = SERVER_URL.startsWith("https://");

if (ADMIN_PASSWORD.length < 12) {
  console.warn("[config] ADMIN_PASSWORD is shorter than 12 characters — it now guards MCP access, use a long random value.");
}

const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/userinfo.email",
];

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

const tokenStore = new TokenStore();

// ---------------------------------------------------------------------------
// Gmail service factory — exchanges stored refresh token for access token
// ---------------------------------------------------------------------------

function makeOAuth2Client() {
  return new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    `${SERVER_URL}/oauth/callback`
  );
}

async function getGmailServiceForAccount(email: string): Promise<GmailService> {
  const refreshToken = tokenStore.getRefreshToken(email);
  if (!refreshToken) {
    throw new Error(
      `Account "${email}" is not connected. Use list_accounts to see connected accounts, or add it via the /setup page.`
    );
  }

  const oauth2 = makeOAuth2Client();
  oauth2.setCredentials({ refresh_token: refreshToken });

  const { token } = await oauth2.getAccessToken();
  if (!token) {
    throw new Error(
      `Failed to get access token for "${email}". The account may need to be re-authorized via /setup.`
    );
  }

  return new GmailService(token);
}

function resolveAccounts(account: string): string[] {
  if (account.toLowerCase() === "all") {
    const all = tokenStore.listAccounts().map((a) => a.email);
    if (all.length === 0) {
      throw new Error("No accounts connected. Add accounts via the /setup page.");
    }
    return all;
  }
  if (!tokenStore.hasAccount(account)) {
    const available = tokenStore.listAccounts().map((a) => a.email);
    throw new Error(
      `Account "${account}" is not connected. Available accounts: ${available.join(", ") || "none"}`
    );
  }
  return [account];
}

// ---------------------------------------------------------------------------
// MCP server factory — registers all tools
// ---------------------------------------------------------------------------

function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "gmail-mcp-server",
    version: "1.0.0",
  });

  // ---- list_accounts ----
  server.tool(
    "list_accounts",
    "List all connected Gmail accounts. Use the email addresses returned here as the 'account' parameter in other tools.",
    {},
    async () => {
      const accounts = tokenStore.listAccounts();
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                connected_accounts: accounts,
                usage_hint:
                  "Use any email address as the 'account' parameter, or use 'all' to query every account.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // ---- list_emails ----
  server.tool(
    "list_emails",
    "Search and list emails. Supports Gmail search syntax (is:unread, from:, newer_than:7d, etc). Use account='all' to search across all connected accounts.",
    {
      account: z
        .string()
        .describe(
          "Email address of the account to search, or 'all' for every connected account"
        ),
      query: z
        .string()
        .optional()
        .describe(
          "Gmail search query (e.g. 'is:unread', 'from:user@example.com newer_than:2d', 'subject:invoice')"
        ),
      max_results: z
        .number()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of emails to return per account (1-100)"),
    },
    async ({ account, query, max_results }) => {
      const accounts = resolveAccounts(account);
      const allResults: Array<{ account: string; emails: any[] }> = [];

      for (const email of accounts) {
        try {
          const gmail = await getGmailServiceForAccount(email);
          const emails = await gmail.listEmails(query, max_results);
          allResults.push({ account: email, emails });
        } catch (err: any) {
          allResults.push({
            account: email,
            emails: [],
          });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(allResults, null, 2),
          },
        ],
      };
    }
  );

  // ---- get_email ----
  server.tool(
    "get_email",
    "Get the full content of a specific email including body, headers, and any unsubscribe links found.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const email = await gmail.getEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account, ...email }, null, 2),
          },
        ],
      };
    }
  );

  // ---- archive_email ----
  server.tool(
    "archive_email",
    "Archive an email by removing it from the inbox. The email remains accessible via search or All Mail.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID to archive"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.archiveEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account,
              ...result,
              message: `Email ${message_id} archived successfully.`,
            }),
          },
        ],
      };
    }
  );

  // ---- apply_label ----
  server.tool(
    "apply_label",
    "Apply a label to an email. Creates the label if it does not already exist.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID"),
      label_name: z
        .string()
        .describe(
          "Label name to apply (e.g. 'Receipts', 'Follow Up'). Created automatically if it does not exist."
        ),
    },
    async ({ account, message_id, label_name }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.applyLabel(message_id, label_name);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account,
              ...result,
              message: `Label "${label_name}" applied to email ${message_id}.`,
            }),
          },
        ],
      };
    }
  );

  // ---- unsubscribe_email ----
  server.tool(
    "unsubscribe_email",
    "Attempt to unsubscribe from a mailing list. Tries List-Unsubscribe header (HTTP and mailto), then scans the email body for unsubscribe links.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z
        .string()
        .describe("The Gmail message ID to unsubscribe from"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.unsubscribeEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account, ...result }, null, 2),
          },
        ],
      };
    }
  );

  // ---- batch_process ----
  server.tool(
    "batch_process",
    "Fetch a batch of emails matching a query for triage. Returns structured data so you can decide which actions to take on each email. Use account='all' to scan all accounts.",
    {
      account: z
        .string()
        .describe(
          "Email address of the account to search, or 'all' for every connected account"
        ),
      query: z
        .string()
        .describe(
          "Gmail search query (e.g. 'is:unread category:promotions', 'newer_than:7d')"
        ),
      max_results: z
        .number()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of emails to fetch per account"),
    },
    async ({ account, query, max_results }) => {
      const accounts = resolveAccounts(account);
      const allResults: Array<{ account: string; emails: any[] }> = [];

      for (const email of accounts) {
        try {
          const gmail = await getGmailServiceForAccount(email);
          const emails = await gmail.batchProcess(query, max_results);
          allResults.push({ account: email, emails });
        } catch (err: any) {
          allResults.push({ account: email, emails: [] });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                total: allResults.reduce((n, r) => n + r.emails.length, 0),
                query,
                results: allResults,
                hint: "Review each email and decide whether to archive, label, unsubscribe, or skip. Use the individual tools with the correct account parameter.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // ---- send_message ----
  server.tool(
    "send_message",
    "Send a new email immediately from one of the connected accounts. This cannot be undone — if the user wants to review it first, use create_draft instead.",
    {
      account: z.string().describe("Email address of the connected account to send from"),
      to: z.array(z.string()).min(1).describe("Recipient email addresses"),
      cc: z.array(z.string()).optional().describe("CC recipients"),
      bcc: z.array(z.string()).optional().describe("BCC recipients"),
      subject: z.string().describe("Email subject"),
      body: z.string().describe("Plain-text email body"),
    },
    async ({ account, to, cc, bcc, subject, body }) => {
      const [email] = resolveAccounts(account);
      const gmail = await getGmailServiceForAccount(email);
      const result = await gmail.sendMessage({ to, cc, bcc, subject, body });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account: email, ...result, message: `Email sent to ${to.join(", ")}.` }),
          },
        ],
      };
    }
  );

  // ---- reply ----
  server.tool(
    "reply",
    "Reply to an existing email in the same thread. Recipients, subject (Re:) and threading headers are derived from the original message. Sends immediately — use create_draft with reply_to_message_id to prepare a reply without sending.",
    {
      account: z.string().describe("Email address of the account the original message belongs to"),
      message_id: z.string().describe("The Gmail message ID to reply to"),
      body: z.string().describe("Plain-text reply body"),
      reply_all: z
        .boolean()
        .default(false)
        .describe("Reply to all original recipients (To + Cc) instead of only the sender"),
    },
    async ({ account, message_id, body, reply_all }) => {
      const [email] = resolveAccounts(account);
      const gmail = await getGmailServiceForAccount(email);
      const result = await gmail.reply(message_id, body, email, reply_all);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account: email, ...result, message: `Reply sent in thread ${result.threadId}.` }),
          },
        ],
      };
    }
  );

  // ---- forward ----
  server.tool(
    "forward",
    "Forward an existing email to other recipients, optionally with a note above the forwarded content. Sends immediately.",
    {
      account: z.string().describe("Email address of the account the original message belongs to"),
      message_id: z.string().describe("The Gmail message ID to forward"),
      to: z.array(z.string()).min(1).describe("Recipient email addresses"),
      body: z.string().optional().describe("Optional note to include above the forwarded message"),
    },
    async ({ account, message_id, to, body }) => {
      const [email] = resolveAccounts(account);
      const gmail = await getGmailServiceForAccount(email);
      const result = await gmail.forward(message_id, to, body);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account: email, ...result, message: `Email forwarded to ${to.join(", ")}.` }),
          },
        ],
      };
    }
  );

  // ---- create_draft ----
  server.tool(
    "create_draft",
    "Create a draft without sending it, so the user can review and send it from Gmail. Pass reply_to_message_id to draft a reply inside an existing thread (recipients and subject are then derived from that message unless overridden).",
    {
      account: z.string().describe("Email address of the connected account the draft belongs to"),
      to: z.array(z.string()).optional().describe("Recipient email addresses (required unless reply_to_message_id is given)"),
      cc: z.array(z.string()).optional().describe("CC recipients"),
      bcc: z.array(z.string()).optional().describe("BCC recipients"),
      subject: z.string().optional().describe("Email subject (required unless reply_to_message_id is given)"),
      body: z.string().describe("Plain-text draft body"),
      reply_to_message_id: z
        .string()
        .optional()
        .describe("Gmail message ID to reply to; the draft is threaded under it"),
      reply_all: z.boolean().default(false).describe("When drafting a reply, include all original recipients"),
    },
    async ({ account, to, cc, bcc, subject, body, reply_to_message_id, reply_all }) => {
      const [email] = resolveAccounts(account);
      const gmail = await getGmailServiceForAccount(email);

      let draftMessage;
      if (reply_to_message_id) {
        const composed = await gmail.composeReply(reply_to_message_id, body, email, reply_all);
        draftMessage = {
          ...composed,
          to: to && to.length > 0 ? to : composed.to,
          cc: cc ?? composed.cc,
          bcc,
          subject: subject ?? composed.subject,
        };
      } else {
        if (!to || to.length === 0) throw new Error("'to' is required when not replying to a message");
        draftMessage = { to, cc, bcc, subject: subject ?? "", body };
      }

      const result = await gmail.createDraft(draftMessage);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account: email,
              ...result,
              to: draftMessage.to,
              subject: draftMessage.subject,
              message: "Draft saved. It has NOT been sent — the user can review and send it from Gmail.",
            }),
          },
        ],
      };
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
// Railway / most PaaS terminate TLS at a proxy; needed for correct client IPs
// in rate limiting and for `secure` cookies.
app.set("trust proxy", TRUST_PROXY);
app.disable("x-powered-by");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------------
// OAuth 2.1 authorization server (protects /mcp; used by the Claude connector)
// ---------------------------------------------------------------------------

const authProvider = new GmailMcpAuthProvider({
  secret: AUTH_SECRET,
  adminPassword: ADMIN_PASSWORD,
  allowedRedirectHosts: ALLOWED_REDIRECT_HOSTS,
  serverUrl: SERVER_URL,
});

// Brute-force protection for the two password forms.
const passwordRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many attempts. Try again later.",
});

// Consent form target — registered before the SDK router so it takes priority.
app.post("/authorize/login", passwordRateLimit, authProvider.handleConsent);

// /.well-known/oauth-authorization-server, /.well-known/oauth-protected-resource/mcp,
// /authorize, /token, /register
app.use(
  mcpAuthRouter({
    provider: authProvider,
    issuerUrl: new URL(SERVER_URL),
    resourceServerUrl: MCP_URL,
    resourceName: "Gmail MCP Server",
    scopesSupported: ["gmail"],
    clientRegistrationOptions: { clientSecretExpirySeconds: 0 },
  })
);

// Some clients look up protected-resource metadata at the root path too.
app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: MCP_URL.href,
    authorization_servers: [new URL(SERVER_URL).href],
    scopes_supported: ["gmail"],
    resource_name: "Gmail MCP Server",
  });
});

// ---------------------------------------------------------------------------
// Admin login (cookie session) — no password in query strings anymore
// ---------------------------------------------------------------------------

const requireAdmin = requireAdminSession(authProvider, "/setup/login");

app.get("/setup/login", (req: Request, res: Response) => {
  if (authProvider.verifySession(readCookie(req, SESSION_COOKIE))) {
    res.redirect("/setup");
    return;
  }
  res.set("Cache-Control", "no-store").type("html").send(renderLoginPage());
});

app.post("/setup/login", passwordRateLimit, (req: Request, res: Response) => {
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!safeEqual(password, ADMIN_PASSWORD)) {
    res.status(401).set("Cache-Control", "no-store").type("html").send(renderLoginPage("Incorrect password."));
    return;
  }
  setSessionCookie(res, authProvider.createSession(), SECURE_COOKIES);
  res.redirect("/setup");
});

app.post("/setup/logout", requireAdmin, (_req: Request, res: Response) => {
  clearSessionCookie(res);
  res.redirect("/setup/login");
});

// ---------------------------------------------------------------------------
// Setup page — manage connected Gmail accounts
// ---------------------------------------------------------------------------

app.get("/setup", requireAdmin, (req: Request, res: Response) => {
  const accounts = tokenStore.listAccounts();
  const message = typeof req.query.message === "string" ? req.query.message : undefined;

  const accountRows = accounts.length > 0
    ? accounts
        .map(
          (a) => `
        <tr>
          <td>${escapeHtml(a.email)}</td>
          <td>${new Date(a.addedAt).toLocaleDateString()}</td>
          <td>
            <form method="POST" action="/setup/remove" style="display:inline">
              <input type="hidden" name="email" value="${escapeHtml(a.email)}" />
              <button type="submit" onclick="return confirm('Remove this account?')" style="color:red;background:none;border:1px solid red;padding:4px 12px;cursor:pointer">Remove</button>
            </form>
          </td>
        </tr>`
        )
        .join("")
    : `<tr><td colspan="3" style="text-align:center;color:#888">No accounts connected yet</td></tr>`;

  res.set("Cache-Control", "no-store").send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Gmail MCP — Setup</title>
      <style>
        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; }
        h1 { font-size: 1.5rem; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eee; }
        th { font-weight: 600; border-bottom: 2px solid #ddd; }
        .btn { display: inline-block; padding: 10px 24px; background: #4285f4; color: white; text-decoration: none; border-radius: 6px; font-size: 14px; }
        .btn:hover { background: #3367d6; }
        .msg { padding: 12px; background: #e8f5e9; border-radius: 6px; margin-bottom: 16px; }
        .msg.error { background: #fce4ec; }
        .logout { float: right; background: none; border: 1px solid #ccc; padding: 6px 12px; border-radius: 6px; cursor: pointer; }
      </style>
    </head>
    <body>
      <form method="POST" action="/setup/logout"><button class="logout" type="submit">Log out</button></form>
      <h1>Gmail MCP Server — Setup</h1>
      ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ""}
      <table>
        <thead><tr><th>Account</th><th>Added</th><th></th></tr></thead>
        <tbody>${accountRows}</tbody>
      </table>
      <a class="btn" href="/oauth/start">+ Add Gmail Account</a>
      ${accounts.length > 0 ? `
      <div style="margin-top:24px;padding:16px;background:#fff3cd;border-radius:6px">
        <strong>Important:</strong> After adding/removing accounts, copy the value below and paste it as the <code>TOKENS_DATA</code> environment variable in Railway. This ensures accounts survive redeploys.
        <div style="margin-top:8px">
          <textarea readonly style="width:100%;height:60px;font-family:monospace;font-size:11px;box-sizing:border-box" onclick="this.select()">${escapeHtml(tokenStore.getTokensDataForExport())}</textarea>
        </div>
      </div>
      ` : ""}
      <hr style="margin-top:40px;border:none;border-top:1px solid #eee" />
      <p style="color:#888;font-size:13px">
        MCP endpoint: <code>${escapeHtml(MCP_URL.href)}</code> (OAuth protected — connect it from Claude and approve with the admin password)<br/>
        Connected accounts: ${accounts.length}
      </p>
    </body>
    </html>
  `);
});

app.post("/setup/remove", requireAdmin, (req: Request, res: Response) => {
  const email = typeof req.body?.email === "string" ? req.body.email : "";

  if (email && tokenStore.hasAccount(email)) {
    tokenStore.removeAccount(email);
    res.redirect(`/setup?message=${encodeURIComponent(`Removed ${email}`)}`);
  } else {
    res.redirect(`/setup?message=${encodeURIComponent("Account not found")}`);
  }
});

// ---------------------------------------------------------------------------
// Google OAuth flow — connects a Gmail account (admin only)
// ---------------------------------------------------------------------------

app.get("/oauth/start", requireAdmin, (req: Request, res: Response) => {
  const session = getAdminSession(req);
  const oauth2 = makeOAuth2Client();
  const url = oauth2.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    state: authProvider.createGoogleState(session.sid),
  });
  res.redirect(url);
});

app.get("/oauth/callback", requireAdmin, async (req: Request, res: Response) => {
  const session = getAdminSession(req);
  const code = typeof req.query.code === "string" ? req.query.code : undefined;
  const state = typeof req.query.state === "string" ? req.query.state : undefined;
  const error = typeof req.query.error === "string" ? req.query.error : undefined;

  const toSetup = (message: string) =>
    res.redirect(`/setup?message=${encodeURIComponent(message)}`);

  // The state is signed and bound to the admin session that started the flow,
  // so a callback URL crafted by someone else cannot attach their account.
  if (!authProvider.verifyGoogleState(state, session.sid)) {
    toSetup("Invalid or expired OAuth state. Please try adding the account again.");
    return;
  }

  if (error) {
    toSetup(`OAuth error: ${error}`);
    return;
  }

  if (!code) {
    toSetup("No authorization code received");
    return;
  }

  try {
    const oauth2 = makeOAuth2Client();
    const { tokens } = await oauth2.getToken(code);

    if (!tokens.refresh_token) {
      toSetup("No refresh token received. Try removing the app from your Google account permissions and re-adding.");
      return;
    }

    // Get the user's email address
    oauth2.setCredentials(tokens);
    const oauth2Api = google.oauth2({ version: "v2", auth: oauth2 });
    const userInfo = await oauth2Api.userinfo.get();
    const email = userInfo.data.email;

    if (!email) {
      toSetup("Could not determine email address");
      return;
    }

    tokenStore.addAccount(email, tokens.refresh_token);
    toSetup(`Successfully connected ${email}`);
  } catch (err: any) {
    console.error("[oauth/callback] Error:", err);
    toSetup(`Error: ${err.message}`);
  }
});

// ---------------------------------------------------------------------------
// Health check — liveness only, reveals nothing about the deployment
// ---------------------------------------------------------------------------

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// ---------------------------------------------------------------------------
// MCP transport — Streamable HTTP (stateless: each request gets a fresh server)
// Every method on /mcp requires a valid OAuth access token.
// ---------------------------------------------------------------------------

const mcpRateLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(
  "/mcp",
  mcpRateLimit,
  requireBearerAuth({
    verifier: authProvider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(MCP_URL),
  })
);

app.post("/mcp", async (req: Request, res: Response) => {
  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless — no session tracking
    });

    const mcpServer = createMcpServer();
    await mcpServer.connect(transport);

    await transport.handleRequest(req, res, req.body);

    // Clean up after response is sent
    res.on("close", () => {
      mcpServer.close().catch(() => {});
      transport.close().catch(() => {});
    });
  } catch (err: any) {
    console.error("[mcp] Error handling request:", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: err.message },
        id: null,
      });
    }
  }
});

app.get("/mcp", async (_req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "SSE streams not supported in stateless mode. Use POST." },
    id: null,
  });
});

app.delete("/mcp", async (_req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "Session management not used in stateless mode." },
    id: null,
  });
});

// Anything else: 404 without leaking what exists.
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "not_found" });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  console.log(`Gmail MCP server listening on port ${PORT}`);
  console.log(`  MCP endpoint:  ${MCP_URL.href} (OAuth 2.1 protected)`);
  console.log(`  Setup page:    ${SERVER_URL}/setup`);
  console.log(`  Health check:  ${SERVER_URL}/health`);
  console.log(`  Accounts:      ${tokenStore.size}`);
});
