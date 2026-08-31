import { google, gmail_v1 } from "googleapis";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EmailSummary {
  id: string;
  threadId: string;
  subject: string;
  from: string;
  date: string;
  snippet: string;
  labelIds: string[];
}

export interface EmailDetail {
  id: string;
  threadId: string;
  subject: string;
  from: string;
  to: string;
  date: string;
  snippet: string;
  body: string;
  labelIds: string[];
  headers: Record<string, string>;
  unsubscribeLinks: string[];
}

export interface UnsubscribeResult {
  success: boolean;
  method: "header-mailto" | "header-http" | "body-link" | "none";
  detail: string;
}

export interface OutgoingMessage {
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  body: string;
  /** Gmail thread to attach the message to (replies/forwards). */
  threadId?: string;
  /** Message-ID header of the message being replied to. */
  inReplyTo?: string;
  /** References header chain for threading. */
  references?: string;
}

export interface SentMessage {
  id: string;
  threadId: string;
}

export interface DraftInfo {
  draftId: string;
  messageId: string;
  threadId: string;
}

// ---------------------------------------------------------------------------
// Pure helpers for composing messages (exported for testing)
// ---------------------------------------------------------------------------

/** Strip CR/LF so a user-supplied value cannot inject extra MIME headers. */
function headerSafe(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim();
}

/** RFC 2047 encode a header value if it contains non-ASCII characters. */
export function encodeHeaderValue(value: string): string {
  const clean = headerSafe(value);
  // eslint-disable-next-line no-control-regex
  if (/^[\x20-\x7e]*$/.test(clean)) return clean;
  return `=?UTF-8?B?${Buffer.from(clean, "utf8").toString("base64")}?=`;
}

/**
 * Build an RFC 2822 message and return it base64url-encoded, as required by
 * the Gmail API's `raw` field. Plain-text body, UTF-8, base64 transfer
 * encoding (safe for any content and line length).
 */
export function buildRawMessage(msg: OutgoingMessage): string {
  const lines: string[] = [];
  const addr = (list?: string[]) => (list ?? []).map(headerSafe).filter(Boolean).join(", ");

  const to = addr(msg.to);
  if (!to) throw new Error("At least one recipient is required");
  lines.push(`To: ${to}`);
  const cc = addr(msg.cc);
  if (cc) lines.push(`Cc: ${cc}`);
  const bcc = addr(msg.bcc);
  if (bcc) lines.push(`Bcc: ${bcc}`);
  lines.push(`Subject: ${encodeHeaderValue(msg.subject)}`);
  if (msg.inReplyTo) lines.push(`In-Reply-To: ${headerSafe(msg.inReplyTo)}`);
  if (msg.references) lines.push(`References: ${headerSafe(msg.references)}`);
  lines.push("MIME-Version: 1.0");
  lines.push('Content-Type: text/plain; charset="UTF-8"');
  lines.push("Content-Transfer-Encoding: base64");
  lines.push("");
  // Wrap base64 body at 76 chars per RFC 2045
  const b64 = Buffer.from(msg.body, "utf8").toString("base64");
  lines.push(...(b64.match(/.{1,76}/g) ?? [""]));

  return Buffer.from(lines.join("\r\n")).toString("base64url");
}

/** Extract bare email addresses from a header like `"Name" <a@b.c>, d@e.f`. */
export function parseAddresses(header: string | undefined): string[] {
  if (!header) return [];
  const out: string[] = [];
  for (const part of header.split(",")) {
    const m = part.match(/<([^>]+)>/) ?? part.match(/([^\s"<>,]+@[^\s"<>,]+)/);
    if (m) out.push(m[1].trim());
  }
  return out;
}

/**
 * Work out who a reply goes to. Honors Reply-To, drops our own address, and
 * de-duplicates case-insensitively.
 */
export function computeReplyRecipients(
  headers: Record<string, string>,
  selfEmail: string,
  replyAll: boolean
): { to: string[]; cc: string[] } {
  const self = selfEmail.toLowerCase();
  const seen = new Set<string>([self]);
  const uniq = (addrs: string[]) =>
    addrs.filter((a) => {
      const k = a.toLowerCase();
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });

  const hdr = (name: string) =>
    Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];

  const replyTarget = parseAddresses(hdr("Reply-To") || hdr("From"));
  const to = uniq(replyTarget);
  if (!replyAll) {
    return { to: to.length > 0 ? to : uniq(parseAddresses(hdr("From"))), cc: [] };
  }
  // Reply-all: original To + Cc go to Cc (minus self and the primary recipient)
  const cc = uniq([...parseAddresses(hdr("To")), ...parseAddresses(hdr("Cc"))]);
  return { to, cc };
}

/** Prefix a subject with Re:/Fwd: unless it already carries that prefix. */
export function prefixSubject(subject: string, prefix: "Re" | "Fwd"): string {
  const s = subject.trim();
  const re = prefix === "Re" ? /^(re|aw|sv)\s*:/i : /^(fwd?|wg|tr)\s*:/i;
  return re.test(s) ? s : `${prefix}: ${s}`;
}

// ---------------------------------------------------------------------------
// Gmail Service — one instance per access token (per session)
// ---------------------------------------------------------------------------

export class GmailService {
  private gmail: gmail_v1.Gmail;

  constructor(accessToken: string) {
    const auth = new google.auth.OAuth2();
    auth.setCredentials({ access_token: accessToken });
    this.gmail = google.gmail({ version: "v1", auth });
  }

  // -----------------------------------------------------------------------
  // list_emails
  // -----------------------------------------------------------------------

  async listEmails(
    query?: string,
    maxResults: number = 20
  ): Promise<EmailSummary[]> {
    const res = await this.gmail.users.messages.list({
      userId: "me",
      q: query || undefined,
      maxResults: Math.min(maxResults, 100),
    });

    const messageIds = res.data.messages ?? [];
    if (messageIds.length === 0) return [];

    // Fetch headers for each message in parallel (batched)
    const summaries = await Promise.all(
      messageIds.map((m) => this.getEmailSummary(m.id!))
    );

    return summaries;
  }

  private async getEmailSummary(messageId: string): Promise<EmailSummary> {
    const res = await this.gmail.users.messages.get({
      userId: "me",
      id: messageId,
      format: "metadata",
      metadataHeaders: ["Subject", "From", "Date"],
    });

    const headers = res.data.payload?.headers ?? [];
    const hdr = (name: string) =>
      headers.find((h) => h.name?.toLowerCase() === name.toLowerCase())
        ?.value ?? "";

    return {
      id: res.data.id!,
      threadId: res.data.threadId!,
      subject: hdr("Subject"),
      from: hdr("From"),
      date: hdr("Date"),
      snippet: res.data.snippet ?? "",
      labelIds: res.data.labelIds ?? [],
    };
  }

  // -----------------------------------------------------------------------
  // get_email
  // -----------------------------------------------------------------------

  async getEmail(messageId: string): Promise<EmailDetail> {
    const res = await this.gmail.users.messages.get({
      userId: "me",
      id: messageId,
      format: "full",
    });

    const headers = res.data.payload?.headers ?? [];
    const hdr = (name: string) =>
      headers.find((h) => h.name?.toLowerCase() === name.toLowerCase())
        ?.value ?? "";

    const headersMap: Record<string, string> = {};
    for (const h of headers) {
      if (h.name && h.value) headersMap[h.name] = h.value;
    }

    const body = this.extractBody(res.data.payload ?? {});
    const unsubscribeLinks = this.parseUnsubscribeLinks(headersMap, body);

    return {
      id: res.data.id!,
      threadId: res.data.threadId!,
      subject: hdr("Subject"),
      from: hdr("From"),
      to: hdr("To"),
      date: hdr("Date"),
      snippet: res.data.snippet ?? "",
      body,
      labelIds: res.data.labelIds ?? [],
      headers: headersMap,
      unsubscribeLinks,
    };
  }

  // -----------------------------------------------------------------------
  // archive_email — remove INBOX label
  // -----------------------------------------------------------------------

  async archiveEmail(messageId: string): Promise<{ success: boolean }> {
    await this.gmail.users.messages.modify({
      userId: "me",
      id: messageId,
      requestBody: {
        removeLabelIds: ["INBOX"],
      },
    });
    return { success: true };
  }

  // -----------------------------------------------------------------------
  // mark_as_read / mark_as_unread — toggle the UNREAD label
  // -----------------------------------------------------------------------

  async setRead(
    messageIds: string[],
    read: boolean
  ): Promise<{ success: boolean; modified: number }> {
    const ids = [...new Set(messageIds.map((id) => id.trim()).filter(Boolean))];
    if (ids.length === 0) throw new Error("At least one message ID is required");

    // batchModify accepts up to 1000 ids per call
    for (let i = 0; i < ids.length; i += 1000) {
      await this.gmail.users.messages.batchModify({
        userId: "me",
        requestBody: {
          ids: ids.slice(i, i + 1000),
          ...(read ? { removeLabelIds: ["UNREAD"] } : { addLabelIds: ["UNREAD"] }),
        },
      });
    }
    return { success: true, modified: ids.length };
  }

  // -----------------------------------------------------------------------
  // apply_label — create if needed, then apply
  // -----------------------------------------------------------------------

  async applyLabel(
    messageId: string,
    labelName: string
  ): Promise<{ success: boolean; labelId: string }> {
    const labelId = await this.getOrCreateLabel(labelName);

    await this.gmail.users.messages.modify({
      userId: "me",
      id: messageId,
      requestBody: {
        addLabelIds: [labelId],
      },
    });

    return { success: true, labelId };
  }

  // -----------------------------------------------------------------------
  // remove_label — strip a label by name from one or more messages
  // -----------------------------------------------------------------------

  async removeLabel(
    messageIds: string[],
    labelName: string
  ): Promise<{ success: boolean; labelId: string | null; modified: number }> {
    const ids = [...new Set(messageIds.map((id) => id.trim()).filter(Boolean))];
    if (ids.length === 0) throw new Error("At least one message ID is required");

    const labelId = await this.findLabelId(labelName);
    if (!labelId) {
      // Nothing to remove — treat as a no-op rather than an error.
      return { success: true, labelId: null, modified: 0 };
    }

    for (let i = 0; i < ids.length; i += 1000) {
      await this.gmail.users.messages.batchModify({
        userId: "me",
        requestBody: { ids: ids.slice(i, i + 1000), removeLabelIds: [labelId] },
      });
    }
    return { success: true, labelId, modified: ids.length };
  }

  /** Resolve a label by name (case-insensitive) or by ID. Returns null if absent. */
  private async findLabelId(labelName: string): Promise<string | null> {
    const res = await this.gmail.users.labels.list({ userId: "me" });
    const labels = res.data.labels ?? [];
    const wanted = labelName.trim().toLowerCase();
    const match = labels.find(
      (l) => l.name?.toLowerCase() === wanted || l.id?.toLowerCase() === wanted
    );
    return match?.id ?? null;
  }

  private async getOrCreateLabel(labelName: string): Promise<string> {
    // Check existing labels
    const res = await this.gmail.users.labels.list({ userId: "me" });
    const existing = (res.data.labels ?? []).find(
      (l) => l.name?.toLowerCase() === labelName.toLowerCase()
    );
    if (existing) return existing.id!;

    // Create new label
    const created = await this.gmail.users.labels.create({
      userId: "me",
      requestBody: {
        name: labelName,
        labelListVisibility: "labelShow",
        messageListVisibility: "show",
      },
    });
    return created.data.id!;
  }

  // -----------------------------------------------------------------------
  // unsubscribe_email
  // -----------------------------------------------------------------------

  async unsubscribeEmail(messageId: string): Promise<UnsubscribeResult> {
    const email = await this.getEmail(messageId);
    const listUnsubscribe = email.headers["List-Unsubscribe"] ?? "";

    // 1. Try HTTP link from List-Unsubscribe header
    const httpLinks = this.extractHttpLinks(listUnsubscribe);
    for (const link of httpLinks) {
      try {
        const resp = await fetch(link, {
          method: "GET",
          redirect: "follow",
          signal: AbortSignal.timeout(10000),
        });
        if (resp.ok) {
          return {
            success: true,
            method: "header-http",
            detail: `Successfully requested unsubscribe via header link: ${link}`,
          };
        }
      } catch {
        // Try next link
      }
    }

    // 2. Try POST to List-Unsubscribe with List-Unsubscribe-Post header
    const postHeader = email.headers["List-Unsubscribe-Post"];
    if (postHeader && httpLinks.length > 0) {
      for (const link of httpLinks) {
        try {
          const resp = await fetch(link, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: postHeader,
            redirect: "follow",
            signal: AbortSignal.timeout(10000),
          });
          if (resp.ok) {
            return {
              success: true,
              method: "header-http",
              detail: `Successfully POSTed unsubscribe via RFC 8058: ${link}`,
            };
          }
        } catch {
          // Try next
        }
      }
    }

    // 3. Try mailto from List-Unsubscribe header
    const mailtoMatch = listUnsubscribe.match(/mailto:([^>,\s]+)/i);
    if (mailtoMatch) {
      const mailtoAddr = mailtoMatch[1];
      try {
        await this.sendUnsubscribeMail(mailtoAddr);
        return {
          success: true,
          method: "header-mailto",
          detail: `Sent unsubscribe email to ${mailtoAddr}`,
        };
      } catch (err) {
        // Fall through
      }
    }

    // 4. Scan body for unsubscribe links
    const bodyLinks = this.extractUnsubscribeLinksFromBody(email.body);
    for (const link of bodyLinks) {
      try {
        const resp = await fetch(link, {
          method: "GET",
          redirect: "follow",
          signal: AbortSignal.timeout(10000),
        });
        if (resp.ok) {
          return {
            success: true,
            method: "body-link",
            detail: `Visited unsubscribe link found in email body: ${link}`,
          };
        }
      } catch {
        // Try next
      }
    }

    // 5. Nothing worked — return the links we found so Claude can inform the user
    const allLinks = [...httpLinks, ...bodyLinks];
    return {
      success: false,
      method: "none",
      detail:
        allLinks.length > 0
          ? `Could not auto-unsubscribe. Found these links the user can try manually:\n${allLinks.join("\n")}`
          : "No unsubscribe mechanism found in this email.",
    };
  }

  private async sendUnsubscribeMail(toAddress: string): Promise<void> {
    // Compose a minimal unsubscribe email
    const raw = Buffer.from(
      [
        `To: ${toAddress}`,
        `Subject: Unsubscribe`,
        `Content-Type: text/plain; charset="UTF-8"`,
        "",
        "Unsubscribe",
      ].join("\r\n")
    )
      .toString("base64url");

    await this.gmail.users.messages.send({
      userId: "me",
      requestBody: { raw },
    });
  }

  // -----------------------------------------------------------------------
  // batch_process — fetch structured data for Claude to decide on
  // -----------------------------------------------------------------------

  async batchProcess(
    query: string,
    maxResults: number = 20
  ): Promise<EmailSummary[]> {
    return this.listEmails(query, maxResults);
  }

  // -----------------------------------------------------------------------
  // send_message — send a new email immediately
  // -----------------------------------------------------------------------

  async sendMessage(msg: OutgoingMessage): Promise<SentMessage> {
    const res = await this.gmail.users.messages.send({
      userId: "me",
      requestBody: { raw: buildRawMessage(msg), threadId: msg.threadId },
    });
    return { id: res.data.id!, threadId: res.data.threadId! };
  }

  // -----------------------------------------------------------------------
  // create_draft — save without sending (optionally as a reply in a thread)
  // -----------------------------------------------------------------------

  async createDraft(msg: OutgoingMessage): Promise<DraftInfo> {
    const res = await this.gmail.users.drafts.create({
      userId: "me",
      requestBody: {
        message: { raw: buildRawMessage(msg), threadId: msg.threadId },
      },
    });
    return {
      draftId: res.data.id!,
      messageId: res.data.message?.id ?? "",
      threadId: res.data.message?.threadId ?? msg.threadId ?? "",
    };
  }

  // -----------------------------------------------------------------------
  // reply / forward — build a threaded message from an existing one
  // -----------------------------------------------------------------------

  /**
   * Compose a reply to `messageId`. Returns the OutgoingMessage so the caller
   * can either send it or save it as a draft.
   */
  async composeReply(
    messageId: string,
    body: string,
    selfEmail: string,
    replyAll: boolean
  ): Promise<OutgoingMessage> {
    const original = await this.getEmail(messageId);
    const { to, cc } = computeReplyRecipients(original.headers, selfEmail, replyAll);
    if (to.length === 0) {
      throw new Error(`Could not determine a reply recipient for message ${messageId}`);
    }

    const messageIdHeader = original.headers["Message-ID"] ?? original.headers["Message-Id"] ?? "";
    const references = [original.headers["References"], messageIdHeader]
      .filter(Boolean)
      .join(" ");

    return {
      to,
      cc,
      subject: prefixSubject(original.subject, "Re"),
      body,
      threadId: original.threadId,
      inReplyTo: messageIdHeader || undefined,
      references: references || undefined,
    };
  }

  async reply(
    messageId: string,
    body: string,
    selfEmail: string,
    replyAll: boolean
  ): Promise<SentMessage> {
    return this.sendMessage(await this.composeReply(messageId, body, selfEmail, replyAll));
  }

  async forward(
    messageId: string,
    to: string[],
    note: string | undefined
  ): Promise<SentMessage> {
    const original = await this.getEmail(messageId);
    const forwardedBlock = [
      "---------- Forwarded message ---------",
      `From: ${original.from}`,
      `Date: ${original.date}`,
      `Subject: ${original.subject}`,
      `To: ${original.to}`,
      "",
      original.body,
    ].join("\n");

    return this.sendMessage({
      to,
      subject: prefixSubject(original.subject, "Fwd"),
      body: note ? `${note}\n\n${forwardedBlock}` : forwardedBlock,
      threadId: original.threadId,
    });
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private extractBody(payload: gmail_v1.Schema$MessagePart): string {
    // Prefer text/plain, fall back to text/html
    if (payload.mimeType === "text/plain" && payload.body?.data) {
      return Buffer.from(payload.body.data, "base64url").toString("utf-8");
    }

    if (payload.mimeType === "text/html" && payload.body?.data) {
      return Buffer.from(payload.body.data, "base64url").toString("utf-8");
    }

    // Multipart: recurse
    if (payload.parts) {
      // Try text/plain first
      for (const part of payload.parts) {
        if (part.mimeType === "text/plain" && part.body?.data) {
          return Buffer.from(part.body.data, "base64url").toString("utf-8");
        }
      }
      // Fall back to text/html
      for (const part of payload.parts) {
        if (part.mimeType === "text/html" && part.body?.data) {
          return Buffer.from(part.body.data, "base64url").toString("utf-8");
        }
      }
      // Recurse into nested multipart
      for (const part of payload.parts) {
        const result = this.extractBody(part);
        if (result) return result;
      }
    }

    return "";
  }

  private parseUnsubscribeLinks(
    headers: Record<string, string>,
    body: string
  ): string[] {
    const links: string[] = [];

    // From List-Unsubscribe header
    const listUnsub = headers["List-Unsubscribe"] ?? "";
    links.push(...this.extractHttpLinks(listUnsub));

    const mailtoMatch = listUnsub.match(/mailto:([^>,\s]+)/i);
    if (mailtoMatch) links.push(`mailto:${mailtoMatch[1]}`);

    // From body
    links.push(...this.extractUnsubscribeLinksFromBody(body));

    return [...new Set(links)];
  }

  private extractHttpLinks(text: string): string[] {
    const matches = text.match(/https?:\/\/[^>,\s<]+/gi);
    return matches ?? [];
  }

  private extractUnsubscribeLinksFromBody(body: string): string[] {
    const links: string[] = [];
    // Match href links near "unsubscribe" text
    const hrefPattern =
      /href\s*=\s*["']?(https?:\/\/[^"'\s>]+(?:unsubscribe|opt.?out|remove|manage.?preferences)[^"'\s>]*)["']?/gi;
    let match;
    while ((match = hrefPattern.exec(body)) !== null) {
      links.push(match[1]);
    }
    // Also match plain URLs with unsubscribe keywords
    const urlPattern =
      /(https?:\/\/\S+(?:unsubscribe|opt.?out|remove|manage.?preferences)\S*)/gi;
    while ((match = urlPattern.exec(body)) !== null) {
      if (!links.includes(match[1])) {
        links.push(match[1]);
      }
    }
    return [...new Set(links)];
  }
}
