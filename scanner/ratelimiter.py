import threading
import time


class RateLimiter:
    def __init__(self, max_per_second=None):
        self.max_per_second = max_per_second if max_per_second and max_per_second > 0 else None
        self._lock = threading.Lock()
        self._next_slot = time.monotonic()

    def wait(self):
        if not self.max_per_second:
            return

        interval = 1.0 / self.max_per_second

        with self._lock:
            now = time.monotonic()
            if self._next_slot < now:
                self._next_slot = now
            sleep_for = self._next_slot - now
            self._next_slot += interval

        if sleep_for > 0:
            time.sleep(sleep_for)
