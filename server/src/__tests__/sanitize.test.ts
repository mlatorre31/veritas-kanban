import { describe, it, expect } from 'vitest';
import {
  stripHtml,
  sanitizeTaskFields,
  sanitizeCommentText,
  sanitizeAuthor,
} from '../utils/sanitize.js';

/**
 * Contract tests for the total-escape sanitizer.
 *
 * `stripHtml()` is `escape(decode(input))`: it first inverts the entities it
 * would emit (`&quot; &lt; &gt; &amp;`, amp last — same as the MCP
 * `decodeEntities`), then escapes `&` (first), `<`, `>`. `"` is left raw. The
 * decode-then-escape composition is idempotent, so re-submitting stored text
 * never compounds entities, and literal entity input round-trips unchanged.
 */

describe('stripHtml (total escape)', () => {
  it('escapes a real tag without dropping content', () => {
    expect(stripHtml('<b>bold</b>')).toBe('&lt;b&gt;bold&lt;/b&gt;');
  });

  it('preserves prose chevrons with spaces/accents verbatim (production repro)', () => {
    // 2026-10-15 production repro: `<suffixe GA température>` must survive
    // untouched — parser-based escape modes dropped/normalized the
    // attribute-like tokens; total escape keeps them byte-for-byte.
    expect(stripHtml('avant <suffixe GA température> après')).toBe(
      'avant &lt;suffixe GA température&gt; après'
    );
  });

  it('keeps arrow/ampersand escaping unchanged', () => {
    expect(stripHtml('a -> b && c')).toBe('a -&gt; b &amp;&amp; c');
  });

  it('leaves comparison operators in plain text untouched', () => {
    expect(stripHtml('x < 3 and y <= z')).toBe('x &lt; 3 and y &lt;= z');
    expect(stripHtml('count < 10')).toBe('count &lt; 10');
  });

  it('escapes a script payload as inert text (no raw tag survives)', () => {
    // XSS-safe: the whole payload becomes text — decoded on render as the
    // literal string `<script>alert(1)</script>`, never parsed as an element,
    // so it can never execute.
    expect(stripHtml('<script>alert(1)</script>')).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('escapes an event-handler attribute as inert text', () => {
    // Same property as above: `onerror` is never materialized as a live
    // attribute — the whole `<img ...>` sequence is text.
    expect(stripHtml('<img onerror=alert(1)>')).toBe('&lt;img onerror=alert(1)&gt;');
  });

  it('stores double quotes raw (old-sanitizer parity)', () => {
    // `"` is not escaped: the old sanitizer stored it raw and nothing renders
    // stored text into HTML attributes, so escaping it only leaks `&quot;`
    // into plain-text surfaces.
    expect(stripHtml('say "hi"')).toBe('say "hi"');
  });
});

describe('stripHtml idempotence', () => {
  const battery = [
    'a -> b && c',
    'avant <suffixe GA température> après',
    '&lt;b&gt;',
    'say "hi" <b> & done',
  ];

  for (const input of battery) {
    it(`is idempotent for ${JSON.stringify(input)}`, () => {
      expect(stripHtml(stripHtml(input))).toBe(stripHtml(input));
    });
  }

  it('is stable for old-data already-encoded arrows (edit cycle)', () => {
    // Stored text from before this change already holds `-&gt;`; a GET→PATCH
    // round-trip decodes then re-escapes it, leaving storage byte-identical.
    expect(stripHtml('a -&gt; b')).toBe('a -&gt; b');
  });

  it('round-trips literal entity input unchanged', () => {
    expect(stripHtml('&lt;b&gt;')).toBe('&lt;b&gt;');
  });
});

describe('sanitizeCommentText', () => {
  it('escapes tags and ampersands in comment text (repro FINDING 2)', () => {
    expect(sanitizeCommentText('x <i>y</i> && z')).toBe('x &lt;i&gt;y&lt;/i&gt; &amp;&amp; z');
  });
});

describe('sanitizeAuthor', () => {
  it('escapes tags in author names', () => {
    expect(sanitizeAuthor('<i>alice</i>')).toBe('&lt;i&gt;alice&lt;/i&gt;');
  });
});

describe('sanitizeTaskFields', () => {
  it('escapes tags on title and description in place', () => {
    const input = { title: '<b>task</b>', description: 'do <i>it</i> now' };
    sanitizeTaskFields(input);
    expect(input.title).toBe('&lt;b&gt;task&lt;/b&gt;');
    expect(input.description).toBe('do &lt;i&gt;it&lt;/i&gt; now');
  });

  it('leaves undefined fields untouched', () => {
    const input: { title?: string; description?: string } = { title: 'plain' };
    sanitizeTaskFields(input);
    expect(input.title).toBe('plain');
    expect(input.description).toBeUndefined();
  });
});
