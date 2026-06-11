import type {
  FileDetail,
  Health,
  Job,
  Listing,
  ProviderInfo,
  Status,
} from "./types";

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(url, init);
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = (await resp.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail);
  }
  return (await resp.json()) as T;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  status: () => request<Status>("/api/status"),
  unlock: (passphrase: string) => request("/api/unlock", json({ passphrase })),
  lock: () => request("/api/lock", { method: "POST" }),

  list: (path: string) =>
    request<Listing>(`/api/files?path=${encodeURIComponent(path)}`),
  fileDetail: (path: string) =>
    request<FileDetail>(`/api/file?path=${encodeURIComponent(path)}`),
  health: (paths: string[]) =>
    request<Record<string, Health>>("/api/health", json({ paths })),
  move: (src: string, dst: string) => request("/api/move", json({ src, dst })),
  deleteFile: (path: string) =>
    request<{ job_id: number }>(`/api/file?path=${encodeURIComponent(path)}`, {
      method: "DELETE",
    }),

  upload: (file: File, path: string, opts: { replicas: number; spread: number }) => {
    const form = new FormData();
    form.append("file", file);
    form.append("path", path.endsWith("/") ? path : path + "/");
    form.append("replicas", String(opts.replicas));
    form.append("spread", String(opts.spread));
    return request<{ job_id: number; vpath: string }>("/api/upload", {
      method: "POST",
      body: form,
    });
  },
  downloadUrl: (path: string) => `/api/download?path=${encodeURIComponent(path)}`,

  jobs: () => request<Job[]>("/api/jobs"),
  providers: () => request<ProviderInfo[]>("/api/providers"),
  scrub: (opts: { deep?: boolean; repair?: boolean }) =>
    request<{ job_id: number }>("/api/scrub", json(opts)),
};

export function humanBytes(n: number | null): string {
  if (n === null) return "?";
  let size = n;
  for (const unit of ["B", "KiB", "MiB", "GiB", "TiB"]) {
    if (size < 1024 || unit === "TiB")
      return unit === "B" ? `${Math.round(size)} B` : `${size.toFixed(1)} ${unit}`;
    size /= 1024;
  }
  return `${n} B`;
}

export function healthDots(minLive: number, target: number): string {
  const live = Math.min(minLive, target);
  return "●".repeat(live) + "○".repeat(Math.max(target - live, 0));
}
