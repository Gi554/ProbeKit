from concurrent.futures import ThreadPoolExecutor
import threading

from .audit import audit
from .store import Store
from .target import Target


class Jobs:
    def __init__(self, store: Store, runner=audit):
        self.store = store
        self.runner = runner
        self.slots = threading.BoundedSemaphore(20)
        self.executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="probekit")

    def submit(self, target: Target, project: str, runner=None, payload=None) -> str:
        if not self.slots.acquire(blocking=False):
            raise ValueError("La file contient déjà 20 audits ; attendez leur fin.")
        try:
            scan_id = self.store.create(target.url, project)
            self.executor.submit(self._run, scan_id, target if payload is None else payload, runner)
        except Exception:
            self.slots.release()
            raise
        return scan_id

    def _run(self, scan_id: str, target, runner=None):
        try:
            self.store.update(scan_id, "running")
            report = (runner or self.runner)(target)
            self.store.update(scan_id, "partial" if report.errors else "done", report)
        except Exception as error:
            self.store.update(scan_id, "failed", error=f"{type(error).__name__}: {error}")
        finally:
            self.slots.release()

    def close(self):
        self.executor.shutdown(wait=True)
