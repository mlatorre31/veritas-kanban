/**
 * Decode the four HTML entities VK's server-side sanitizer (`sanitize-html`,
 * `allowedTags: []`) emits on task title/description and comment text.
 *
 * The VK web UI decodes these on render, but MCP readers get the raw
 * entities (`->` as `-&gt;`, `&&` as `&amp;&amp;`). This module decodes them
 * on the read side so agents see the text as written.
 */

/**
 * Replace `&quot;`, `&lt;`, `&gt;`, and finally `&amp;` — in that order.
 * `&amp;` must be last so already-encoded ampersands (`&amp;lt;`, which
 * represents the literal text `&lt;`) do not double-decode.
 */
export function decodeEntities(s: string): string {
  return s
    .replaceAll('&quot;', '"')
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&amp;', '&');
}

/**
 * Shallow copy with `title`/`description` decoded when they are strings, and
 * each entry of `comments` passed through `decodeCommentText` when the array
 * is present (the server embeds comments in the task object, so `get_task`
 * and `list_tasks` carry comment text too).
 */
export function decodeTaskText<
  T extends { title?: string; description?: string; comments?: { text?: string }[] },
>(t: T): T {
  const copy = { ...t };
  if (typeof copy.title === 'string') {
    copy.title = decodeEntities(copy.title);
  }
  if (typeof copy.description === 'string') {
    copy.description = decodeEntities(copy.description);
  }
  if (Array.isArray(copy.comments)) {
    copy.comments = copy.comments.map(decodeCommentText);
  }
  return copy;
}

/** Shallow copy with `text` decoded when it is a string. */
export function decodeCommentText<T extends { text?: string }>(c: T): T {
  const copy = { ...c };
  if (typeof copy.text === 'string') {
    copy.text = decodeEntities(copy.text);
  }
  return copy;
}
