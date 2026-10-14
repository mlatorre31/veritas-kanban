/**
 * Unit tests for the entity-decode helpers.
 *
 * Server-free: unlike the other tests in this directory, these never touch
 * a live VK server — they exercise the pure string/object helpers directly.
 */
import { describe, it, expect } from 'vitest';
import {
  decodeEntities,
  decodeTaskText,
  decodeCommentText,
} from '../utils/decode.js';

describe('decodeEntities', () => {
  it('decodes the four sanitize-html entities in one pass', () => {
    expect(decodeEntities('a -&gt; b &amp;&amp; c &lt;= d &quot;q&quot;')).toBe(
      'a -> b && c <= d "q"',
    );
  });

  it('decodes &amp; last so &amp;lt; becomes &lt;, not <', () => {
    expect(decodeEntities('&amp;lt;')).toBe('&lt;');
  });

  it('decodes a double-escaped ampersand once', () => {
    expect(decodeEntities('&amp;amp;')).toBe('&amp;');
  });

  it('returns text without entities unchanged', () => {
    expect(decodeEntities('plain text, no entities here')).toBe(
      'plain text, no entities here',
    );
  });

  it('returns the empty string unchanged', () => {
    expect(decodeEntities('')).toBe('');
  });

  it('passes a literal NBSP through untouched', () => {
    expect(decodeEntities('a\u00a0b')).toBe('a\u00a0b');
  });
});

describe('decodeTaskText', () => {
  it('decodes title and description and leaves other fields alone', () => {
    const input = {
      id: 't1',
      title: 'x &amp; y',
      description: '-&gt;',
      created: '2026-10-13',
    };
    const decoded = decodeTaskText(input);
    expect(decoded).toEqual({
      id: 't1',
      title: 'x & y',
      description: '->',
      created: '2026-10-13',
    });
  });

  it('leaves an undefined description undefined', () => {
    const input: { title: string; description?: string } = { title: 'only title' };
    const decoded = decodeTaskText(input);
    expect(decoded.title).toBe('only title');
    expect('description' in decoded).toBe(false);
    expect(decoded.description).toBeUndefined();
  });

  it('returns a shallow copy rather than mutating the input', () => {
    const input = { title: 'x &amp; y' };
    const decoded = decodeTaskText(input);
    expect(decoded).not.toBe(input);
    expect(input.title).toBe('x &amp; y');
  });

  it('decodes embedded comment text and leaves other comment fields alone', () => {
    const input = {
      id: 't2',
      title: 'task',
      comments: [{ id: 'c1', text: 'a &amp;&amp; b', author: 'agent' }],
    };
    expect(decodeTaskText(input)).toEqual({
      id: 't2',
      title: 'task',
      comments: [{ id: 'c1', text: 'a && b', author: 'agent' }],
    });
  });

  it('does not add a comments key when the task has none', () => {
    const decoded = decodeTaskText({ title: 'no comments' });
    expect('comments' in decoded).toBe(false);
  });
});

describe('decodeCommentText', () => {
  it('decodes text and leaves other fields alone', () => {
    const input = { id: 'c1', text: 'a &amp;&amp; b', author: 'agent' };
    expect(decodeCommentText(input)).toEqual({
      id: 'c1',
      text: 'a && b',
      author: 'agent',
    });
  });

  it('leaves an undefined text undefined', () => {
    const input: { author: string; text?: string } = { author: 'agent' };
    const decoded = decodeCommentText(input);
    expect(decoded.author).toBe('agent');
    expect('text' in decoded).toBe(false);
    expect(decoded.text).toBeUndefined();
  });
});
