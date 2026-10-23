import time
import threading
from collections import defaultdict, deque

WINDOW_SECONDS = 600     # 10 minutes
MAX_PER_IP = 5           # requests per visitor per window

_hits = defaultdict(deque)     # key -> the moments of that key's recent attempts
_lock = threading.Lock()


def allow(key, limit, window=WINDOW_SECONDS):
    now = time.monotonic()
    with _lock:
        hits = _hits[key]
        # forget attempts that fall outside the window
        while hits and now - hits[0] > window:         # the oldest moment is more than `window` seconds ago
            hits.popleft()
        if len(hits) >= limit:
            return False              # too many: refuse
        hits.append(now)
        return True                 # fine: allow