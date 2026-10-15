/**
 * Server-side HTML sanitization for XSS defense-in-depth.
 *
 * The web frontend already sanitizes via DOMPurify, but non-browser API
 * consumers (mobile apps, CLI tools, third-party integrations) could be
 * vulnerable to stored XSS if the server stores payloads verbatim.
 *
 * Policy (total escape, never discard):
 *   - Task titles:      entity-escape ALL markup characters (no raw HTML stored)
 *   - Task descriptions: entity-escape ALL markup characters (no raw HTML stored — markdown is rendered client-side)
 *   - Comments:          entity-escape ALL markup characters
 *   - Author names:      entity-escape ALL markup characters
 *
 * Tag-like input (valid tags, prose chevrons, attribute-like tokens alike) is
 * entity-escaped at storage time rather than parsed or deleted, so text is
 * preserved losslessly. Stored text is never raw markup; consumers that render
 * HTML decode entities to text (the web UI decodes on render; the MCP decodes
 * on read). The escape set — `&` `&lt;` `&gt;` `&quot;` — is exactly the four the
 * MCP `decodeEntities` inverts (amp last), so reads are a perfect round trip.
 *
 * @see docs/SECURITY_AUDIT_2026-01-28.md — MED-1
 */

import path from 'path';

// ─── Path Traversal Prevention ─────────────────────────────────────────────────

/**
 * Validate that a path segment (filename, ID, etc.) does not contain
 * directory traversal characters.
 *
 * Rejects segments containing: '..', '/', '\', null bytes.
 * Use on any user-supplied string before interpolating into a filesystem path.
 *
 * @throws {Error} if the segment contains traversal characters
 * @see docs/SECURITY_AUDIT_2026-01-28.md — HIGH-1 (path traversal)
 */
export function validatePathSegment(segment: string): string {
  if (!segment || typeof segment !== 'string') {
    throw new Error('Path segment must be a non-empty string');
  }
  if (
    segment.includes('..') ||
    segment.includes('/') ||
    segment.includes('\\') ||
    segment.includes('\0')
  ) {
    throw new Error('Invalid path segment: contains directory traversal characters');
  }
  return segment;
}

/**
 * Ensure that a resolved target path is within the expected base directory.
 * Prevents path traversal attacks by verifying the canonical path prefix.
 *
 * @throws {Error} if target resolves to a location outside base
 */
export function ensureWithinBase(base: string, target: string): string {
  const resolvedBase = path.resolve(base);
  const resolvedTarget = path.resolve(target);
  if (resolvedTarget !== resolvedBase && !resolvedTarget.startsWith(resolvedBase + path.sep)) {
    throw new Error('Path traversal detected: target is outside the base directory');
  }
  return resolvedTarget;
}

/**
 * Entity-escape the four markup characters `&`, `<`, `>`, `"` — in that order
 * (`&` first, so already-encoded entities double-escape and never decode back
 * into raw markup). Total escape, not tag parsing: nothing is dropped, so
 * prose chevrons round-trip verbatim.
 *
 * - Real tags are escaped, content preserved: `<b>bold</b>` → `&lt;b&gt;bold&lt;/b&gt;`
 * - Prose chevrons with spaces/accents survive: `avant <suffixe GA température> après`
 *   → `avant &lt;suffixe GA température&gt; après`
 * - Payloads become inert text, not raw markup: `<script>alert(1)</script>`
 *   → `&lt;script&gt;alert(1)&lt;/script&gt;` (rendered/decoded as text, never executed)
 * - Already-encoded input double-escapes: `&lt;b&gt;` → `&amp;lt;b&amp;gt;`
 *
 * The escape set is exactly what `mcp/src/utils/decode.ts` `decodeEntities`
 * inverts (`&quot; &lt; &gt; &amp;`, `&amp;` last), keeping reads lossless.
 */
export function stripHtml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

/**
 * Sanitize task fields in-place on a create/update payload.
 * Only sanitizes fields that are present (defined) on the input.
 */
export function sanitizeTaskFields(input: { title?: string; description?: string }): void {
  if (input.title !== undefined) {
    input.title = stripHtml(input.title);
  }
  if (input.description !== undefined) {
    input.description = stripHtml(input.description);
  }
}

/**
 * Sanitize comment text.
 */
export function sanitizeCommentText(text: string): string {
  return stripHtml(text);
}

/**
 * Sanitize author name.
 */
export function sanitizeAuthor(author: string): string {
  return stripHtml(author);
}
