// Typed fetch wrapper for the public API.

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function api<T>(path: string, params?: object): Promise<T> {
  const url = new URL(path, location.origin);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
  }
  const res = await fetch(url.toString());
  if (!res.ok) {
    let detail: string = res.statusText;
    try {
      const body = (await res.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      // non-JSON error body — keep statusText
    }
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}
