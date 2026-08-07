// Loading / empty / error states.

export function skeletonFeedHtml(): string {
  return `
    <div class="skeleton-feed" aria-hidden="true">
      <div class="sk-line w40"></div>
      <div class="sk-line"></div>
      <div class="sk-line w60"></div>
      <div class="sk-line w40"></div>
      <div class="sk-line"></div>
      <div class="sk-line w60"></div>
    </div>`;
}

export function emptyStateHtml(title = "没有找到符合条件的内容", hint = "尝试调整分类、时间或热度筛选。"): string {
  return `
    <div class="empty-state">
      <div class="empty-title">${title}</div>
      <div class="empty-hint">${hint}</div>
    </div>`;
}

export function errorStateHtml(message: string, onRetry: () => void): string {
  const root = document.createElement("div");
  root.className = "error-state";
  root.innerHTML = `
    <div class="error-title">内容加载失败</div>
    <div class="dim" style="font-size:12px;margin-bottom:14px">${message}</div>
    <button class="btn btn-primary" data-action="retry">重新加载</button>`;
  root.addEventListener("click", (event) => {
    if ((event.target as HTMLElement | null)?.closest('[data-action="retry"]')) onRetry();
  });
  return root.outerHTML;
}
