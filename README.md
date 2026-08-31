# Gmail MCP Server

### Multi-Account Gmail for AI Agents & Assistants

An open-source [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that gives AI agents and assistants full read and write access to Gmail. Connect multiple Gmail accounts, search emails, archive, label, and auto-unsubscribe. All through one server.

![Gmail MCP Server Banner](banner.png)

Works with **Claude**, **OpenClaw**, **Cursor**, **Windsurf**, **Cline**, **Continue**, and any MCP-compatible client.

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new/template?template=https://github.com/navbuildz/gmail-mcp-server)

---

## Why This Exists

Most AI tools ship with a Gmail integration that can only read emails from a single account. No archiving. No labeling. No unsubscribing. And if you use multiple Gmail accounts? You're out of luck.

This MCP server fixes that. One server, all your accounts, full read and write access.

## Gmail MCP Server vs Built-in Connectors

| Feature | Built-in Gmail (Claude) | Gmail MCP Server |
|---|---|---|
| Read emails | Yes | Yes |
| Write / modify emails | No | **Yes** |
| Multiple Gmail accounts | No | **Yes** |
| Archive emails | No | **Yes** |
| Apply labels | No | **Yes** |
| Auto-unsubscribe | No | **Yes** |
| Works with OpenClaw | No | **Yes** |
| Works with Cursor | No | **Yes** |
| Works with Windsurf | No | **Yes** |
| Works with Cline | No | **Yes** |
| Open source | No | **Yes** |

---

## What is an MCP Server?

[Model Context Protocol (MCP)](https://modelcontextprotocol.io) is an open standard that lets AI agents and assistants connect to external tools and data sources. An MCP server exposes tools that any compatible client can call. Think of it as a plugin system for AI.

This Gmail MCP server turns any MCP-compatible AI client into a full-featured email agent.

---

## Gmail MCP Server Features

- **Multi-account support.** Connect multiple Gmail accounts and switch between them, or query all at once.
- **Full read and write access.** Not just reading emails. Send, reply, forward, draft, archive, label, and unsubscribe.
- **Gmail search syntax.** Use Gmail's query language: `is:unread`, `from:`, `newer_than:7d`, `has:attachment`, and more.
- **Auto-unsubscribe.** Finds and triggers unsubscribe links automatically. Supports List-Unsubscribe headers, mailto links, and body link scanning.
- **Batch operations.** Fetch batches of emails for AI-powered triage and bulk actions.
- **Secure by design.** The `/mcp` endpoint is protected by OAuth 2.1 (PKCE) — only clients you approve with the admin password can use it. AES-256-GCM encrypted token storage, minimal Gmail scopes.
- **Deploy anywhere.** Railway, Docker, or your own server.

---

## Available Tools

| Tool | Description |
|---|---|
| `list_accounts` | List all connected Gmail accounts |
| `list_emails` | Search and list emails using Gmail query syntax. Supports `account="all"` |
| `get_email` | Get full email content, headers, and parsed unsubscribe links |
| `archive_email` | Archive an email by removing it from the inbox |
| `mark_as_read` | Mark one or more emails as read |
| `mark_as_unread` | Mark one or more emails as unread |
| `apply_label` | Apply a label to an email. Creates the label if it doesn't exist |
| `remove_label` | Remove a label (by name) from one or more emails |
| `unsubscribe_email` | Auto-unsubscribe from mailing lists and newsletters |
| `batch_process` | Fetch a batch of emails for triage. Supports `account="all"` |
| `send_message` | Send a new email (to/cc/bcc, subject, plain-text body) |
| `reply` | Reply (or reply-all) to a message in its thread, with proper `In-Reply-To`/`References` headers |
| `forward` | Forward a message to other recipients, optionally with a note |
| `create_draft` | Save a draft instead of sending — new message or a threaded reply — for the user to review in Gmail |

---

## Setup Guide: Deploy in 5 Minutes

### Prerequisites

1. A [Google Cloud](https://console.cloud.google.com) project with the **Gmail API** enabled
2. OAuth 2.0 credentials (Web application type)
3. A hosting platform ([Railway](https://railway.app), your own server, or Docker)

### Step 1: Google Cloud Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com) and create a new project
2. Enable the **Gmail API** (APIs & Services → Library → search "Gmail API" → Enable)
3. Configure the **OAuth consent screen**:
   - User type: External
   - Add scopes: `gmail.readonly`, `gmail.modify`
   - Add your Gmail addresses as test users
4. Create **OAuth credentials**:
   - APIs & Services → Credentials → Create Credentials → OAuth client ID
   - Application type: Web application
   - Authorized redirect URI: `https://your-server-url/oauth/callback`
   - Save the **Client ID** and **Client Secret**

### Step 2: Deploy

#### Option A: Deploy to Railway (Recommended)

1. Click the Deploy button above, or create a new project on [Railway](https://railway.app) connected to this repo
2. Add these environment variables:

| Variable | Value |
|---|---|
| `GOOGLE_CLIENT_ID` | Your OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | Your OAuth Client Secret |
| `ENCRYPTION_KEY` | Any random string (32+ characters) |
| `ADMIN_PASSWORD` | Long random password. It guards the setup page **and** approves MCP clients, so treat it like an API key (`openssl rand -base64 24`) |
| `SERVER_URL` | Your Railway app URL (e.g., `https://your-app.railway.app`) |
| `PORT` | `3000` |

Optional:

| Variable | Default | Purpose |
|---|---|---|
| `AUTH_SECRET` | `ENCRYPTION_KEY` | Signs OAuth tokens and admin sessions. Change it to instantly invalidate every connected client |
| `ALLOWED_REDIRECT_HOSTS` | `claude.ai,claude.com` | Comma-separated hosts allowed as OAuth redirect targets. Add `localhost` for MCP Inspector, or your client's callback host for other tools |
| `TRUST_PROXY` | `true` | Set to `false` if the server is not behind a reverse proxy |

3. Generate a domain in Railway (Service → Settings → Networking → Generate Domain)
4. Update `SERVER_URL` with the generated domain
5. Update the **Authorized redirect URI** in Google Cloud Console to `https://your-domain.railway.app/oauth/callback`

#### Option B: Self-Host

```bash
git clone https://github.com/navbuildz/gmail-mcp-server.git
cd gmail-mcp-server
npm install
cp .env.example .env
# Edit .env with your values
npm run build
npm start
```

##### Run at boot on Windows

Self-hosting on a Windows machine? After `npm run build` and creating `.env`, register a Scheduled Task from an **elevated** PowerShell:

```powershell
.\scripts\install-windows-task.ps1            # runs as your user (asks for your password once)
.\scripts\install-windows-task.ps1 -AsSystem  # or run as LOCAL SYSTEM
```

The task starts `node --env-file=.env dist\index.js` at boot, restarts it if it crashes, never times out, and writes output to `logs\server.log`. After pulling an update, rebuild and restart it:

```powershell
git pull; npm run build
Stop-ScheduledTask -TaskName "Gmail MCP Server"; Start-ScheduledTask -TaskName "Gmail MCP Server"
```

Remove it with `.\scripts\install-windows-task.ps1 -Uninstall`.

#### Option C: Docker

```bash
docker build -t gmail-mcp-server .
docker run -p 3000:3000 \
  -e GOOGLE_CLIENT_ID=your-client-id \
  -e GOOGLE_CLIENT_SECRET=your-client-secret \
  -e ENCRYPTION_KEY=your-random-string \
  -e ADMIN_PASSWORD=your-password \
  -e SERVER_URL=https://your-domain.com \
  gmail-mcp-server
```

### Step 3: Connect Gmail Accounts

1. Visit `https://your-server-url/setup`
2. Enter your admin password
3. Click **+ Add Gmail Account**
4. Sign in with Google and grant permissions
5. Repeat for each Gmail account you want to connect

> **Railway users:** After adding accounts, copy the `TOKENS_DATA` value shown on the setup page and add it as an environment variable in Railway. This keeps your accounts connected across redeploys.

---

## How to Connect Gmail MCP Server to Claude

1. Go to [Claude](https://claude.ai) → Settings → Connectors
2. Click **+** → Add custom connector
3. Fill in:
   - **Name**: `Gmail` (or any name you prefer)
   - **Remote MCP server URL**: `https://your-server-url/mcp`
   - Leave OAuth fields blank (the server supports dynamic client registration)
4. Click **Add**, then **Connect**. Claude opens your server's authorization page — enter your `ADMIN_PASSWORD` and click **Allow**
5. Start a new conversation and try: *"List my connected Gmail accounts"*

Nobody can use the `/mcp` endpoint without completing that step, and the authorization page only accepts redirects back to `claude.ai` / `claude.com` (see `ALLOWED_REDIRECT_HOSTS`).

---

## How to Connect Gmail MCP Server to Cursor

Add to your Cursor MCP settings (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "gmail": {
      "url": "https://your-server-url/mcp"
    }
  }
}
```

Cursor will open the server's authorization page in your browser the first time — enter your `ADMIN_PASSWORD`. Cursor's OAuth callback runs on `localhost`, so set `ALLOWED_REDIRECT_HOSTS=claude.ai,claude.com,localhost` on the server.

---

## How to Connect Gmail MCP Server to Windsurf

Add to your Windsurf MCP configuration:

```json
{
  "mcpServers": {
    "gmail": {
      "serverUrl": "https://your-server-url/mcp"
    }
  }
}
```

Like Cursor, Windsurf completes OAuth via a `localhost` callback — add `localhost` to `ALLOWED_REDIRECT_HOSTS` and approve with your `ADMIN_PASSWORD` when the browser opens.

---

## Multi-Account Gmail Setup

Connect as many Gmail accounts as you need. Every tool accepts an `account` parameter:

- Use a specific email: `"account": "user@gmail.com"`
- Query all accounts at once: `"account": "all"`

**Example prompts you can try:**
- *"Show me unread emails from the last 2 days across all accounts"*
- *"Archive all promotional emails in user@gmail.com"*
- *"Unsubscribe from newsletters in all accounts"*
- *"Find emails with attachments from the last week in work@gmail.com"*

---

## Auto-Unsubscribe from Newsletters with AI

The `unsubscribe_email` tool handles the entire unsubscribe process:

1. Checks the `List-Unsubscribe` header (RFC 8058 one-click POST)
2. Tries HTTP unsubscribe links from the header
3. Sends an unsubscribe email via `mailto:` links
4. Scans the email body for unsubscribe URLs
5. Returns manual links if automatic unsubscribe isn't possible

Try it: *"Find newsletters from the last month and unsubscribe from all of them"*

---

## Supported MCP Clients

| Client | Status | Configuration |
|---|---|---|
| [Claude](https://claude.ai) (Web, Desktop, Code) | Supported | Custom connector → Remote MCP server URL |
| [OpenClaw](https://openclaw.com) | Supported | MCP configuration |
| [Cursor](https://cursor.com) | Supported | `.cursor/mcp.json` |
| [Windsurf](https://codeium.com/windsurf) | Supported | MCP configuration |
| [Cline](https://github.com/cline/cline) | Supported | MCP settings |
| [Continue](https://continue.dev) | Supported | MCP configuration |
| Any MCP-compatible client | Supported | Point to the `/mcp` endpoint (client must support OAuth 2.1 with dynamic client registration; add its callback host to `ALLOWED_REDIRECT_HOSTS`) |

---

## Architecture

```
AI Agent / Assistant (Claude, OpenClaw, Cursor, Windsurf, Cline)
  ↓ MCP Protocol (Streamable HTTP)
Gmail MCP Server (Railway / Self-hosted / Docker)
  ├── /mcp             MCP endpoint (tools) — requires OAuth bearer token
  ├── /authorize       OAuth 2.1 consent page (admin password) + /token, /register,
  │                    /.well-known/oauth-* discovery
  ├── /setup           Admin page (add/remove accounts) — cookie session
  ├── /oauth/callback  Google OAuth callback (admin session + signed state)
  └── Token Store      Encrypted refresh tokens
        ↓
Gmail API (per-account OAuth tokens)
```

---

## Security

- **Protected MCP endpoint.** `/mcp` requires an OAuth 2.1 access token. Tokens are only issued after you approve a client with `ADMIN_PASSWORD` on the server's consent page; PKCE (S256) is mandatory and authorization codes are single-use and short-lived
- **Restricted client registration.** Dynamic registration is open (the Claude connector needs it), but redirect URIs must point at `ALLOWED_REDIRECT_HOSTS`, so a stranger cannot register a client that would receive your authorization codes
- **Stateless, revocable tokens.** Access (1h) and refresh (30d) tokens are HMAC-signed with `AUTH_SECRET` (defaults to `ENCRYPTION_KEY`) — nothing to persist across redeploys; rotate the secret to disconnect every client at once
- **No secrets in URLs.** The admin password is never placed in a query string; `/setup` uses an HttpOnly, SameSite cookie session, and the Google OAuth `state` is a signed nonce bound to that session
- **Brute-force protection.** Password forms are limited to 10 attempts per 15 minutes per IP; `/mcp` and the OAuth endpoints are rate-limited too
- **OAuth 2.0** for authentication with Google
- **AES-256-GCM** encrypted refresh token storage
- **Minimal scopes** using only `gmail.readonly` and `gmail.modify`
- **No passwords stored.** Your Gmail password never touches the server
- **Revocable anytime** from [Google Account Permissions](https://myaccount.google.com/permissions)
- `/health` returns only `{"status":"ok"}`; every other route is either authenticated or a standard OAuth discovery endpoint

---

## Gmail Search Query Examples

The `list_emails` and `batch_process` tools accept Gmail's full search syntax:

| Query | What it finds |
|---|---|
| `is:unread` | Unread emails |
| `is:unread newer_than:2d` | Unread emails from the last 2 days |
| `from:user@example.com` | Emails from a specific sender |
| `subject:invoice` | Emails with "invoice" in the subject |
| `has:attachment` | Emails with attachments |
| `category:promotions` | Promotional emails |
| `newer_than:7d` | Emails from the last week |
| `after:2025/01/01 before:2025/02/01` | Emails in a date range |
| `label:important is:unread` | Unread important emails |
| `larger:5M` | Emails larger than 5MB |

---

## Contributing

Want to help make this better? Here are some open ideas:

- [x] Add `send_message` tool for composing and sending emails
- [x] Add `reply` / `forward` / `create_draft` tools
- [ ] Add HTML bodies and attachments to outgoing messages
- [ ] Add email attachment download support
- [ ] Add `delete_email` tool
- [x] Add `mark_as_read` / `mark_as_unread` tools
- [x] Add `remove_label` tool
- [ ] Add support for Google Workspace accounts

PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Tech Stack

- **Runtime**: Node.js 20+
- **Language**: TypeScript
- **MCP SDK**: [@modelcontextprotocol/sdk](https://github.com/modelcontextprotocol/typescript-sdk)
- **Gmail API**: [googleapis](https://github.com/googleapis/google-api-nodejs-client)
- **HTTP**: Express 5
- **Auth**: Google OAuth 2.0 (Gmail access), OAuth 2.1 + PKCE authorization server (MCP clients)

---

## License

[MIT](LICENSE)

---

If this project is useful to you, give it a star. It helps others find it.
