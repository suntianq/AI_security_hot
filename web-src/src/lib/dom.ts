// DOM + escaping helpers. esc() is the single HTML-escaping entry point.

export function esc(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function qs<T extends Element>(selector: string, root: ParentNode = document): T | null {
  return root.querySelector<T>(selector);
}

export function qsAll<T extends Element>(selector: string, root: ParentNode = document): T[] {
  return Array.from(root.querySelectorAll<T>(selector));
}

export function mount(root: ParentNode, html: string): void {
  root.replaceChildren();
  const template = document.createElement("template");
  template.innerHTML = html;
  root.append(...template.content.childNodes);
}

/** Attach a one-time delegated click handler that matches a data-action. */
export function onAction(
  root: ParentNode,
  action: string,
  handler: (target: HTMLElement) => void,
): void {
  root.addEventListener("click", (event) => {
    const target = (event.target as HTMLElement | null)?.closest<HTMLElement>(
      `[data-action="${action}"]`,
    );
    if (target) handler(target);
  });
}
