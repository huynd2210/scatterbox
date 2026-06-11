import { useEffect, useState } from "react";
import { api, humanBytes } from "../api";
import type { DaemonEvent, Job } from "../types";

interface Progress {
  done: number;
  total: number;
}

/** Background job queue: seeded from /api/jobs, kept live by /ws events
 * (the lastEvent prop re-renders us; progress is per-chunk from put_file). */
export function Transfers({ lastEvent }: { lastEvent: DaemonEvent | null }) {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [progress, setProgress] = useState<Record<number, Progress>>({});

  useEffect(() => {
    api.jobs().then(setJobs).catch(() => {});
  }, [lastEvent?.type === "job" && lastEvent.state]);

  useEffect(() => {
    if (
      lastEvent?.type === "job" &&
      lastEvent.id !== undefined &&
      lastEvent.done !== undefined &&
      lastEvent.total !== undefined
    ) {
      setProgress((old) => ({
        ...old,
        [lastEvent.id!]: { done: lastEvent.done!, total: lastEvent.total! },
      }));
    }
  }, [lastEvent]);

  if (jobs.length === 0) return <p className="muted empty">no transfers yet</p>;

  return (
    <div className="transfers">
      {jobs.map((job) => (
        <JobRow key={job.id} job={job} progress={progress[job.id]} />
      ))}
    </div>
  );
}

function describe(job: Job): string {
  const p = job.payload;
  switch (job.kind) {
    case "upload":
      return `upload ${String(p.vpath ?? "?")}`;
    case "delete":
      return `delete ${String(p.vpath ?? "?")}`;
    case "scrub":
      return `scrub${p.deep ? " (deep)" : ""}${p.repair ? " + repair" : ""}`;
    default:
      return job.kind;
  }
}

function JobRow({ job, progress }: { job: Job; progress?: Progress }) {
  const pct =
    job.state === "done"
      ? 100
      : progress && progress.total > 0
        ? Math.floor((progress.done / progress.total) * 100)
        : null;
  const error = job.result && "error" in job.result ? String(job.result.error) : null;
  return (
    <div className={`job ${job.state}`}>
      <div className="job-head">
        <span className="job-title">{describe(job)}</span>
        <span className={`job-state ${job.state}`}>{job.state}</span>
      </div>
      {job.state === "running" && (
        <div className="bar">
          <div
            className="fill"
            style={{ width: pct !== null ? `${pct}%` : "8%" }}
          />
        </div>
      )}
      {progress && job.state === "running" && (
        <span className="muted small">
          {humanBytes(progress.done)} / {humanBytes(progress.total)}
        </span>
      )}
      {job.kind === "scrub" && job.state === "done" && job.result && (
        <span className="muted small">
          probed {String(job.result.probed)}, suspect{" "}
          {String(job.result.marked_suspect)}, lost {String(job.result.marked_lost)}
          {Number(job.result.repaired) > 0 && `, repaired ${String(job.result.repaired)}`}
        </span>
      )}
      {error && <span className="error small">{error}</span>}
    </div>
  );
}
