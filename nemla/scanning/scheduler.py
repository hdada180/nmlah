"""The scheduler behind every scan: bounded, fair and quick to stop.

* Jobs are pulled from a (possibly enormous) iterable only as workers free up,
  so scanning 65,535 ports on thousands of hosts never builds a queue of
  futures: memory stays proportional to the number of workers.
* One global limit on concurrent jobs and one limit per host, so a single
  target is never hammered with every worker.
* An optional rate limiter (token bucket) and a probe budget.
* Cancellation: nothing new is started once the cancel event is set, and
  running jobs see the same event through the cancellable network helpers.
"""
from __future__ import annotations

import collections
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from ..log import logger
from ..net import Cancelled, sleep_cancellable


class RateLimiter:
    """Token bucket: at most `rate` acquisitions per second. `rate <= 0` means unlimited."""

    def __init__(self, rate: float, burst=None):
        self.rate = max(0.0, float(rate or 0))
        self.capacity = float(burst) if burst else max(1.0, self.rate / 10.0)
        self._tokens = self.capacity
        self._stamp = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, cancel=None, n: int = 1) -> bool:
        """Wait for `n` tokens. Returns False if the cancel event ended the wait."""
        if not self.rate:
            return True
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._stamp) * self.rate)
                self._stamp = now
                if self._tokens >= n:
                    self._tokens -= n
                    return True
                wait_for = (n - self._tokens) / self.rate
            if not sleep_cancellable(min(wait_for, 0.05), cancel):
                return False


class ProbeBudget:
    """A cap on the total number of connections/datagrams a scan may open (0 = no cap)."""

    def __init__(self, limit: int = 0):
        self.limit = max(0, int(limit or 0))
        self.used = 0
        self.exhausted = False
        self._lock = threading.Lock()

    def take(self, n: int = 1) -> bool:
        with self._lock:
            if self.limit and self.used + n > self.limit:
                self.exhausted = True
                return False
            self.used += n
            return True


class Job:
    """One unit of work. `key` groups jobs that share a per-host limit; `arg` is
    whatever the caller wants back with the result."""

    __slots__ = ("arg", "fn", "key", "kind", "limiter")

    def __init__(self, key, fn, arg=None, kind: str = "", limiter=None):
        self.key, self.fn, self.arg, self.kind, self.limiter = key, fn, arg, kind, limiter


class JobFailed:
    """Result of a job that raised. The scan goes on; the error is only counted."""

    def __init__(self, error: BaseException):
        self.error = error


CANCELLED = object()


def is_failure(result) -> bool:
    return result is CANCELLED or isinstance(result, JobFailed)


class Scheduler:
    def __init__(self, workers: int, per_key=None, cancel=None, diagnostics=None, window=None):
        self.workers = max(1, int(workers))
        self.per_key = max(1, int(per_key)) if per_key else self.workers
        self.cancel = cancel if cancel is not None else threading.Event()
        self.diagnostics = diagnostics
        self.window = max(8, int(window)) if window else self.workers * 4
        self._extra: collections.deque = collections.deque()

    def add(self, job: Job) -> None:
        """Queue a follow-up job (called by the consumer while iterating `results`)."""
        self._extra.append(job)

    def _call(self, job: Job):
        if self.cancel.is_set():
            return CANCELLED
        try:
            return job.fn()
        except Cancelled:
            return CANCELLED
        except Exception as exc:
            logger.debug("job %s failed", job.kind or job.key, exc_info=True)
            if self.diagnostics is not None:
                self.diagnostics.warn("job_error", f"{job.kind or 'job'}: {type(exc).__name__}")
            return JobFailed(exc)

    def results(self, jobs):
        """Run `jobs` and yield (job, result) in completion order.

        Failed jobs yield a JobFailed, jobs dropped by cancellation yield CANCELLED.
        """
        source = iter(jobs)
        deferred: collections.deque = collections.deque()   # pulled from `source` but their key is busy
        inflight: dict = {}
        busy: collections.Counter = collections.Counter()
        finished: queue.SimpleQueue = queue.SimpleQueue()   # completed futures, pushed by the workers
        source_done = False
        pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="nemla")

        def take_eligible(queue):
            for _ in range(len(queue)):
                job = queue.popleft()
                if busy[job.key] < self.per_key:
                    return job
                queue.append(job)
            return None

        def next_job():
            nonlocal source_done
            job = take_eligible(self._extra) or take_eligible(deferred)
            while job is None and not source_done and len(deferred) < self.window:
                try:
                    candidate = next(source)
                except StopIteration:
                    source_done = True
                    break
                if busy[candidate.key] < self.per_key:
                    job = candidate
                else:
                    deferred.append(candidate)
            return job

        try:
            while True:
                while len(inflight) < self.workers and not self.cancel.is_set():
                    job = next_job()
                    if job is None:
                        break
                    if job.limiter is not None and not job.limiter.acquire(self.cancel):
                        break
                    future = pool.submit(self._call, job)
                    inflight[future] = job
                    busy[job.key] += 1
                    future.add_done_callback(finished.put)
                if not inflight:
                    return
                try:
                    batch = [finished.get(timeout=0.2)]
                except queue.Empty:
                    continue
                while True:                  # take everything else that is already done
                    try:
                        batch.append(finished.get_nowait())
                    except queue.Empty:
                        break
                for future in batch:
                    job = inflight.pop(future)
                    busy[job.key] -= 1
                    yield job, future.result()
        finally:
            for fut in inflight:
                fut.cancel()
            pool.shutdown(wait=False)


def imap(func, items, workers: int, cancel=None, diagnostics=None):
    """Run func(item) for every item on a bounded pool; yield (item, result) as each finishes.

    Items that raise are skipped (and counted in `diagnostics`); when `cancel` is
    set the generator stops early.
    """
    scheduler = Scheduler(workers, cancel=cancel, diagnostics=diagnostics)
    jobs = (Job(None, (lambda item=item: func(item)), arg=item) for item in items)
    for job, result in scheduler.results(jobs):
        if not is_failure(result):
            yield job.arg, result
