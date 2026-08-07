// URL query helpers — filter state is mirrored into the query string so
// refresh/share/back-forward all keep working.

export function readQuery(): URLSearchParams {
  return new URLSearchParams(location.search);
}

export function updateQuery(partial: Record<string, string | undefined>): void {
  const params = readQuery();
  for (const [key, value] of Object.entries(partial)) {
    if (value === undefined || value === "") params.delete(key);
    else params.set(key, value);
  }
  const qs = params.toString();
  const next = `${location.pathname}${qs ? `?${qs}` : ""}`;
  history.replaceState(null, "", next);
}
