/**
 * In-process registry of AbortControllers for running AI jobs.
 *
 * `cancelAiJob` used to flip the row to `cancelled` while the provider call
 * kept running to completion. With the async HTTP client every job gets a
 * signal; aborting it tears down the in-flight request immediately.
 */
const controllers = new Map<string, AbortController>();

export function registerJobAbort(jobId: string): AbortSignal {
  const existing = controllers.get(jobId);
  if (existing) return existing.signal;
  const controller = new AbortController();
  controllers.set(jobId, controller);
  return controller.signal;
}

export function releaseJobAbort(jobId: string): void {
  controllers.delete(jobId);
}

/** Abort a running job. Returns false when no live controller is registered
 *  (job already finished, or was started by a previous process). */
export function abortJob(jobId: string, reason = "cancelled by operator"): boolean {
  const controller = controllers.get(jobId);
  if (!controller) return false;
  controller.abort(new Error(reason));
  controllers.delete(jobId);
  return true;
}

export function isJobAborted(signal: AbortSignal | undefined): boolean {
  return !!signal?.aborted;
}
