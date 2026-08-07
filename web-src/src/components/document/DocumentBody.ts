// Document body renderer — Markdown + LaTeX interleaved. Ported from the old
// document.js tokenizer: marked would otherwise escape \[...\] and break
// KaTeX's block delimiters, so math and text tokens are rendered separately
// and concatenated in their original order.

import { marked } from "marked";
import katex from "katex";
import "katex/dist/katex.min.css";

marked.setOptions({ breaks: true, gfm: true });

type Token = string | { math: true; display: boolean; expr: string };

export function renderDocumentBody(text: string | null): string {
  if (!text) return '<div class="dim">该来源只有摘要，无完整正文。</div>';

  const tokens: Token[] = [];
  const re = /\\\[([\s\S]*?)\\\]|\$([^$\n]+)\$/g;
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    if (match.index > last) tokens.push(text.slice(last, match.index));
    if (match[1] !== undefined) tokens.push({ math: true, display: true, expr: match[1] });
    else tokens.push({ math: true, display: false, expr: match[2] });
    last = match.index + match[0].length;
  }
  if (last < text.length) tokens.push(text.slice(last));

  return tokens
    .map((token) => {
      if (typeof token === "string") {
        return token.trim() ? marked.parse(token) : "";
      }
      const html = katex.renderToString(token.expr, {
        displayMode: token.display,
        throwOnError: false,
      });
      return token.display ? `<div class="math-block">${html}</div>` : html;
    })
    .join("");
}
