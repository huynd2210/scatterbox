// Typed client for the daemon's HTTP API (see docs/FEATURES.md §12 for
// the endpoint reference). Every helper throws an Error carrying the
// daemon's `detail` message, so components can show it verbatim.
import type {
  FileDetail,
  Health,
  Job,
  Listing,
  NewProvider,
  PolicyInfo,
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
  init: (passphrase: string) => request("/api/init", json({ passphrase })),
  importBackup: (files: File[], passphrase: string) => {
    const form = new FormData();
    for (const f of files) form.append("files", f);
    form.append("passphrase", passphrase);
    return request<{ files: number; restored_from: string }>("/api/import", {
      method: "POST",
      body: form,
    });
  },
  exportUrl: "/api/export",
  recover: (body: {
    passphrase: string;
    type: string;
    root?: string;
    client_id?: string;
    client_secret?: string;
    name?: string;
  }) =>
    request<{ files: number; adopted: string | null; pending_reauth: string[] }>(
      "/api/recover",
      json(body),
    ),
  reauthProvider: (name: string, body: { client_id?: string; client_secret?: string }) =>
    request(`/api/providers/${encodeURIComponent(name)}/reauth`, json(body)),
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

  upload: (
    file: File,
    path: string,
    opts: { replicas?: number; spread?: number } = {},
  ) => {
    const form = new FormData();
    form.append("file", file);
    form.append("path", path.endsWith("/") ? path : path + "/");
    // unset = inherit from the folder policy
    if (opts.replicas !== undefined) form.append("replicas", String(opts.replicas));
    if (opts.spread !== undefined) form.append("spread", String(opts.spread));
    return request<{ job_id: number; vpath: string }>("/api/upload", {
      method: "POST",
      body: form,
    });
  },

  policy: (path: string) =>
    request<PolicyInfo>(`/api/policy?path=${encodeURIComponent(path)}`),
  setPolicy: (path: string, fields: Record<string, unknown>) =>
    request("/api/policy", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, ...fields }),
    }),
  clearPolicy: (path: string) =>
    request(`/api/policy?path=${encodeURIComponent(path)}`, { method: "DELETE" }),
  downloadUrl: (path: string) => `/api/download?path=${encodeURIComponent(path)}`,

  jobs: () => request<Job[]>("/api/jobs"),
  providers: () => request<ProviderInfo[]>("/api/providers"),
  addProvider: (p: NewProvider) => request("/api/providers", json(p)),
  removeProvider: (name: string, force = false) =>
    request(`/api/providers/${encodeURIComponent(name)}?force=${force}`, {
      method: "DELETE",
    }),
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
