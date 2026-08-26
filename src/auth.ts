import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Request, Response, NextFunction } from "express";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import {
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { redirectUriMatches } from "@modelcontextprotocol/sdk/server/auth/handlers/authorize.js";

// ---------------------------------------------------------------------------
// OAuth 2.1 authorization server for the MCP endpoint
//
// Everything is STATELESS: clients, authorization codes, access tokens and
// refresh tokens are all HMAC-SHA256 signed blobs. Nothing needs to be
// persisted, so tokens survive redeploys (Railway) and multiple instances.
//
// Security model:
//   - Only the admin (ADMIN_PASSWORD) can authorize a client. The consent page
//     is rate limited.
//   - Dynamic client registration is open (required by the Claude connector),
//     but redirect URIs are restricted to an allowlist of hosts, so a stranger
//     cannot register a client that receives codes for *their* callback.
//   - PKCE (S256) is mandatory — enforced by the SDK's token handler.
//   - Authorization codes are single-use (in-memory replay guard) and short
//     lived.
//   - Rotating AUTH_SECRET (or ENCRYPTION_KEY if AUTH_SECRET is unset)
//     invalidates every issued token immediately.
// ---------------------------------------------------------------------------

const ACCESS_TOKEN_TTL = 60 * 60; // 1 hour
const REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60; // 30 days
const AUTH_CODE_TTL = 5 * 60; // 5 minutes
const AUTH_REQUEST_TTL = 10 * 60; // 10 minutes to type the password
const SESSION_TTL = 8 * 60 * 60; // admin session on /setup
const GRANTED_SCOPES = ["gmail"];

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

// ---------------------------------------------------------------------------
// Signing primitives
// ---------------------------------------------------------------------------

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

type TokenKind =
  | "client"
  | "authreq"
  | "code"
  | "access"
  | "refresh"
  | "session"
  | "gstate";

interface BasePayload {
  t: TokenKind;
  iat: number;
  exp?: number;
}

class Signer {
  private readonly key: Buffer;

  constructor(secret: string) {
    // Domain-separate from the token-store encryption key.
    this.key = createHmac("sha256", "gmail-mcp-oauth-signing").update(secret).digest();
  }

  sign(payload: BasePayload): string {
    const body = b64url(JSON.stringify(payload));
    const mac = b64url(createHmac("sha256", this.key).update(body).digest());
    return `${body}.${mac}`;
  }

  /** Verifies signature, kind and expiry. Returns null on any failure. */
  verify<T extends BasePayload>(token: string | undefined, kind: TokenKind): T | null {
    if (!token || typeof token !== "string") return null;
    const dot = token.indexOf(".");
    if (dot <= 0) return null;
    const body = token.slice(0, dot);
    const mac = token.slice(dot + 1);
    const expected = b64url(createHmac("sha256", this.key).update(body).digest());
    if (!safeEqual(mac, expected)) return null;
    let payload: T;
    try {
      payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    } catch {
      return null;
    }
    if (!payload || payload.t !== kind) return null;
    if (typeof payload.exp === "number" && payload.exp < nowSec()) return null;
    return payload;
  }

  /** Deterministic secret for a client id (so client secrets need no storage). */
  clientSecretFor(clientId: string): string {
    return createHmac("sha256", this.key).update(`client-secret:${clientId}`).digest("hex");
  }
}

// ---------------------------------------------------------------------------
// Payload shapes
// ---------------------------------------------------------------------------

interface ClientPayload extends BasePayload {
  t: "client";
  ru: string[]; // redirect_uris
  n?: string; // client_name
  am?: string; // token_endpoint_auth_method
}

interface AuthRequestPayload extends BasePayload {
  t: "authreq";
  cid: string;
  ru: string;
  cc: string; // code_challenge
  st?: string;
  sc: string[];
  rs?: string; // resource
}

interface CodePayload extends BasePayload {
  t: "code";
  cid: string;
  ru: string;
  cc: string;
  sc: string[];
  rs?: string;
  jti: string;
}

interface AccessPayload extends BasePayload {
  t: "access";
  cid: string;
  sc: string[];
  rs?: string;
  jti: string;
}

interface RefreshPayload extends BasePayload {
  t: "refresh";
  cid: string;
  sc: string[];
  rs?: string;
  jti: string;
}

interface SessionPayload extends BasePayload {
  t: "session";
  sid: string;
}

interface GoogleStatePayload extends BasePayload {
  t: "gstate";
  sid: string; // bound to the admin session that started the flow
  nonce: string;
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export interface AuthConfig {
  /** Secret used to sign every token. */
  secret: string;
  /** Password the admin types on the consent page. */
  adminPassword: string;
  /** Hostnames allowed as OAuth redirect targets (exact match or subdomain). */
  allowedRedirectHosts: string[];
  /** Public URL of the server (issuer). */
  serverUrl: string;
}

export class GmailMcpAuthProvider implements OAuthServerProvider {
  private readonly signer: Signer;
  private readonly cfg: AuthConfig;
  private readonly usedCodes = new Map<string, number>(); // jti -> exp

  constructor(cfg: AuthConfig) {
    this.cfg = cfg;
    this.signer = new Signer(cfg.secret);
  }

  // ---- Client store (stateless: the client id *is* the registration) ----

  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (clientId: string) => this.getClient(clientId),
      registerClient: (client) => this.registerClient(client),
    };
  }

  private getClient(clientId: string): OAuthClientInformationFull | undefined {
    const p = this.signer.verify<ClientPayload>(clientId, "client");
    if (!p) return undefined;
    const isPublic = p.am === "none";
    return {
      client_id: clientId,
      client_id_issued_at: p.iat,
      client_name: p.n,
      redirect_uris: p.ru,
      token_endpoint_auth_method: p.am,
      client_secret: isPublic ? undefined : this.signer.clientSecretFor(clientId),
      // never expires — rotate AUTH_SECRET to invalidate everything
      client_secret_expires_at: undefined,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    };
  }

  private registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">
  ): OAuthClientInformationFull {
    if (!Array.isArray(client.redirect_uris) || client.redirect_uris.length === 0) {
      throw new InvalidClientMetadataError("redirect_uris is required");
    }
    for (const uri of client.redirect_uris) {
      this.assertAllowedRedirectUri(uri);
    }

    const payload: ClientPayload = {
      t: "client",
      iat: nowSec(),
      ru: client.redirect_uris,
      n: client.client_name,
      am: client.token_endpoint_auth_method ?? "client_secret_post",
    };
    const clientId = this.signer.sign(payload);
    return this.getClient(clientId)!;
  }

  private assertAllowedRedirectUri(uri: string): void {
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      throw new InvalidClientMetadataError(`Invalid redirect_uri: ${uri}`);
    }
    const host = url.hostname.toLowerCase();
    const isLoopback = LOOPBACK_HOSTS.has(host);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback)) {
      throw new InvalidClientMetadataError(`redirect_uri must use https: ${uri}`);
    }
    const allowed = this.cfg.allowedRedirectHosts.some(
      (h) => host === h || host.endsWith(`.${h}`)
    );
    if (!allowed) {
      console.warn(
        `[oauth] Rejected client registration with redirect host "${host}". ` +
          `Allowed: ${this.cfg.allowedRedirectHosts.join(", ")} (ALLOWED_REDIRECT_HOSTS)`
      );
      throw new InvalidClientMetadataError(
        `redirect_uri host "${host}" is not allowed. Set ALLOWED_REDIRECT_HOSTS to permit it.`
      );
    }
  }

  // ---- Authorization (consent page) ----

  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const request: AuthRequestPayload = {
      t: "authreq",
      iat: nowSec(),
      exp: nowSec() + AUTH_REQUEST_TTL,
      cid: client.client_id,
      ru: params.redirectUri,
      cc: params.codeChallenge,
      st: params.state,
      sc: params.scopes ?? [],
      rs: params.resource?.href,
    };
    res
      .status(200)
      .set("Cache-Control", "no-store")
      .type("html")
      .send(renderConsentPage(this.signer.sign(request), client, params.redirectUri));
  }

  /**
   * Express handler for POST /authorize/login — the consent form target.
   * Verifies the admin password, then redirects back to the client with a code.
   */
  handleConsent = (req: Request, res: Response): void => {
    const requestToken = typeof req.body?.request === "string" ? req.body.request : undefined;
    const password = typeof req.body?.password === "string" ? req.body.password : "";

    const request = this.signer.verify<AuthRequestPayload>(requestToken, "authreq");
    if (!request) {
      res
        .status(400)
        .type("html")
        .send(renderMessagePage("Authorization request expired", "Go back to Claude and start connecting again."));
      return;
    }

    // Re-validate the redirect target at consent time: it must still match a
    // registered URI (loopback ports may vary, per RFC 8252) AND still be on
    // the *current* allowlist, so narrowing ALLOWED_REDIRECT_HOSTS takes effect
    // for clients registered earlier.
    const client = this.getClient(request.cid);
    let redirectAllowed = false;
    if (client && client.redirect_uris.some((registered) => redirectUriMatches(request.ru, registered))) {
      try {
        this.assertAllowedRedirectUri(request.ru);
        redirectAllowed = true;
      } catch {
        redirectAllowed = false;
      }
    }
    if (!client || !redirectAllowed) {
      res.status(400).type("html").send(renderMessagePage("Invalid client", "Unknown client or redirect URI."));
      return;
    }

    if (!safeEqual(password, this.cfg.adminPassword)) {
      res
        .status(401)
        .set("Cache-Control", "no-store")
        .type("html")
        .send(renderConsentPage(requestToken!, client, request.ru, "Incorrect password."));
      return;
    }

    const code: CodePayload = {
      t: "code",
      iat: nowSec(),
      exp: nowSec() + AUTH_CODE_TTL,
      cid: request.cid,
      ru: request.ru,
      cc: request.cc,
      sc: GRANTED_SCOPES,
      rs: request.rs,
      jti: randomBytes(16).toString("hex"),
    };

    const redirect = new URL(request.ru);
    redirect.searchParams.set("code", this.signer.sign(code));
    if (request.st) redirect.searchParams.set("state", request.st);
    res.redirect(302, redirect.href);
  };

  // ---- Code exchange ----

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const code = this.signer.verify<CodePayload>(authorizationCode, "code");
    if (!code || code.cid !== client.client_id) {
      throw new InvalidGrantError("Invalid or expired authorization code");
    }
    return code.cc;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    _resource?: URL
  ): Promise<OAuthTokens> {
    const code = this.signer.verify<CodePayload>(authorizationCode, "code");
    if (!code || code.cid !== client.client_id) {
      throw new InvalidGrantError("Invalid or expired authorization code");
    }
    if (redirectUri !== undefined && redirectUri !== code.ru) {
      throw new InvalidGrantError("redirect_uri does not match");
    }
    this.pruneUsedCodes();
    if (this.usedCodes.has(code.jti)) {
      throw new InvalidGrantError("Authorization code already used");
    }
    this.usedCodes.set(code.jti, code.exp ?? nowSec() + AUTH_CODE_TTL);

    return this.issueTokens(client.client_id, code.sc, code.rs);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    _scopes?: string[],
    _resource?: URL
  ): Promise<OAuthTokens> {
    const rt = this.signer.verify<RefreshPayload>(refreshToken, "refresh");
    if (!rt || rt.cid !== client.client_id) {
      throw new InvalidGrantError("Invalid or expired refresh token");
    }
    return this.issueTokens(client.client_id, rt.sc, rt.rs);
  }

  private issueTokens(clientId: string, scopes: string[], resource?: string): OAuthTokens {
    const iat = nowSec();
    const access: AccessPayload = {
      t: "access",
      iat,
      exp: iat + ACCESS_TOKEN_TTL,
      cid: clientId,
      sc: scopes,
      rs: resource,
      jti: randomBytes(16).toString("hex"),
    };
    const refresh: RefreshPayload = {
      t: "refresh",
      iat,
      exp: iat + REFRESH_TOKEN_TTL,
      cid: clientId,
      sc: scopes,
      rs: resource,
      jti: randomBytes(16).toString("hex"),
    };
    return {
      access_token: this.signer.sign(access),
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL,
      scope: scopes.join(" "),
      refresh_token: this.signer.sign(refresh),
    };
  }

  private pruneUsedCodes(): void {
    const now = nowSec();
    for (const [jti, exp] of this.usedCodes) {
      if (exp < now) this.usedCodes.delete(jti);
    }
  }

  // ---- Bearer verification (used by requireBearerAuth on /mcp) ----

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const p = this.signer.verify<AccessPayload>(token, "access");
    if (!p) throw new InvalidTokenError("Invalid or expired access token");
    return {
      token,
      clientId: p.cid,
      scopes: p.sc,
      expiresAt: p.exp,
      resource: p.rs ? new URL(p.rs) : undefined,
    };
  }

  // ---- Admin session for /setup (cookie based, no secrets in URLs) ----

  createSession(): string {
    const iat = nowSec();
    const s: SessionPayload = { t: "session", iat, exp: iat + SESSION_TTL, sid: randomBytes(16).toString("hex") };
    return this.signer.sign(s);
  }

  verifySession(token: string | undefined): SessionPayload | null {
    return this.signer.verify<SessionPayload>(token, "session");
  }

  /** State for the Google OAuth flow, bound to the admin session. */
  createGoogleState(sessionId: string): string {
    const iat = nowSec();
    const s: GoogleStatePayload = {
      t: "gstate",
      iat,
      exp: iat + AUTH_REQUEST_TTL,
      sid: sessionId,
      nonce: randomBytes(16).toString("hex"),
    };
    return this.signer.sign(s);
  }

  verifyGoogleState(state: string | undefined, sessionId: string): boolean {
    const p = this.signer.verify<GoogleStatePayload>(state, "gstate");
    return !!p && safeEqual(p.sid, sessionId);
  }
}

// ---------------------------------------------------------------------------
// Cookie helpers (tiny, to avoid another dependency)
// ---------------------------------------------------------------------------

export const SESSION_COOKIE = "gmail_mcp_admin";

export function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() === name) {
      try {
        return decodeURIComponent(part.slice(idx + 1).trim());
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

export function setSessionCookie(res: Response, value: string, secure: boolean): void {
  res.cookie(SESSION_COOKIE, value, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_TTL * 1000,
  });
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, { path: "/" });
}

/** Express middleware factory: require a valid admin session cookie. */
export function requireAdminSession(provider: GmailMcpAuthProvider, loginPath: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const session = provider.verifySession(readCookie(req, SESSION_COOKIE));
    if (!session) {
      if (req.method === "GET") {
        res.redirect(loginPath);
      } else {
        res.status(401).send("Unauthorized");
      }
      return;
    }
    (req as Request & { adminSession: SessionPayload }).adminSession = session;
    next();
  };
}

export function getAdminSession(req: Request): SessionPayload {
  return (req as Request & { adminSession: SessionPayload }).adminSession;
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const PAGE_STYLE = `
  body { font-family: system-ui, sans-serif; max-width: 420px; margin: 80px auto; padding: 0 20px; color: #222; }
  h2 { margin-bottom: 4px; }
  p { color: #555; }
  input[type=password] { padding: 10px; width: 100%; box-sizing: border-box; margin: 12px 0; font-size: 15px; }
  button { padding: 10px 24px; background: #4285f4; color: #fff; border: 0; border-radius: 6px; font-size: 15px; cursor: pointer; }
  .err { color: #b00020; margin: 8px 0; }
  code { background: #f3f3f3; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
`;

function renderConsentPage(
  requestToken: string,
  client: OAuthClientInformationFull,
  redirectUri: string,
  error?: string
): string {
  const name = client.client_name ? escapeHtml(client.client_name) : "An MCP client";
  const host = escapeHtml(new URL(redirectUri).hostname);
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Gmail MCP — Authorize</title><style>${PAGE_STYLE}</style></head>
<body>
  <h2>Authorize access</h2>
  <p><strong>${name}</strong> (<code>${host}</code>) is asking for access to your Gmail MCP server.</p>
  <form method="POST" action="/authorize/login" autocomplete="off">
    <input type="hidden" name="request" value="${escapeHtml(requestToken)}" />
    <input type="password" name="password" placeholder="Admin password" autofocus required />
    ${error ? `<div class="err">${escapeHtml(error)}</div>` : ""}
    <button type="submit">Allow</button>
  </form>
</body></html>`;
}

export function renderMessagePage(title: string, body: string): string {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title><style>${PAGE_STYLE}</style></head>
<body><h2>${escapeHtml(title)}</h2><p>${escapeHtml(body)}</p></body></html>`;
}

export function renderLoginPage(error?: string): string {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Gmail MCP — Admin Login</title><style>${PAGE_STYLE}</style></head>
<body>
  <h2>Admin Login</h2>
  <form method="POST" action="/setup/login" autocomplete="off">
    <input type="password" name="password" placeholder="Admin password" autofocus required />
    ${error ? `<div class="err">${escapeHtml(error)}</div>` : ""}
    <button type="submit">Login</button>
  </form>
</body></html>`;
}
