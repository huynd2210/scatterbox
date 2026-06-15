// Mirrors the daemon's JSON shapes (daemon/scatterbox_daemon/app.py).

export interface FileEntry {
  name: string;
  vpath: string;
  size: number;
  mtime: number;
}

export interface Listing {
  path: string;
  dirs: string[];
  files: FileEntry[];
}

export interface Health {
  health: "healthy" | "degraded" | "at-risk" | "lost" | string;
  min_live: number;
  replica_target: number;
  scheme?: "replica" | "ec" | string;
}

export interface PolicyValues {
  replicas: number;
  min_spread: number;
  spread_mode: string;
  spread_cap: number | null;
  scheme: "replica" | "ec" | string;
  ec_k: number;
  ec_n: number;
  pinned: string[];
  excluded: string[];
}

export interface PolicyInfo {
  path: string;
  effective: PolicyValues;
  source: string | null; // folder it came from; null = defaults
  explicit: Record<string, unknown> | null; // set on this exact folder?
}

export interface Job {
  id: number;
  kind: string;
  state: "pending" | "running" | "done" | "failed" | string;
  payload: Record<string, unknown>;
  result: Record<string, unknown> | null;
  created_at: number;
  updated_at: number | null;
}

export interface ProviderQuota {
  total: number | null;
  used: number;
  confidence: "exact" | "estimated" | "unknown" | string;
}

export interface ProviderInfo {
  id: number;
  name: string;
  type: string;
  max_object_bytes: number | null;
  replicas_held: number;
  latency_class?: string;
  quota: ProviderQuota | null;
  reliability: number | null;
  error: string | null;
}

export interface Status {
  initialized: boolean;
  locked: boolean;
  files: number;
  providers: number;
  chunks_at_floor: number;
  chunks_total: number;
  jobs_pending: number;
}

export interface ProviderBreakdown {
  name: string;
  type: string;
  states: Record<string, number>;
}

export interface FileDetail {
  vpath: string;
  size: number;
  mtime: number;
  chunk_size: number;
  replica_target: number;
  min_spread: number;
  scheme: "replica" | "ec" | string;
  ec_k: number | null;
  health: string;
  min_live: number;
  providers: ProviderBreakdown[];
}

export interface NewProvider {
  name: string;
  type: "localfs" | "gdrive" | "onedrive" | "dropbox" | "pcloud" | "koofr" | "tigris";
  root?: string;
  client_id?: string;
  client_secret?: string;
  // koofr authenticates with an app password (HTTP Basic), not OAuth.
  email?: string;
  app_password?: string;
  // tigris (S3-compatible) authenticates with an S3 access key pair; the bucket
  // is non-secret config (the endpoint is fixed).
  access_key_id?: string;
  secret_access_key?: string;
  bucket?: string;
  max_object_bytes?: number | null;
  capacity_bytes?: number | null;
}

// One message on /ws. type "job" carries lifecycle + optional progress;
// type "files-changed" tells the explorer to re-list.
export interface DaemonEvent {
  type: "job" | "files-changed" | string;
  id?: number;
  kind?: string;
  state?: string;
  done?: number;
  total?: number;
  payload?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: string;
}
