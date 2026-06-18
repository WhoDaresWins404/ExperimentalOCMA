import time


class TimeBudgetManager:
    """Allocates and reallocates scan time dynamically across scanners."""

    def __init__(self, total_budget: int = 3600):
        self.total = total_budget
        self._remaining = total_budget
        self._allocated: dict[str, int] = {}
        self._start_time: float = 0.0

    def start(self):
        self._start_time = time.time()

    @property
    def elapsed(self) -> int:
        return int(time.time() - self._start_time) if self._start_time else 0

    @property
    def remaining(self) -> int:
        return max(0, self.total - self.elapsed - sum(self._allocated.values()))

    def allocate(self, scanner_name: str, weight: float = 0.15) -> int:
        """Give a scanner a slice of remaining budget proportional to its weight."""
        budget = max(30, int(self.remaining * weight))
        self._allocated[scanner_name] = budget
        return budget

    def surplus(self, scanner_name: str, used: int) -> int:
        """Return unused budget from a scanner back to the pool."""
        allocated = self._allocated.pop(scanner_name, 0)
        unused = max(0, allocated - used)
        return unused

    def emergency_fund(self, scanner_name: str, amount: int) -> bool:
        """Grant extra time to a scanner mid-run if budget permits."""
        if self.remaining >= amount:
            self._allocated[scanner_name] = self._allocated.get(scanner_name, 0) + amount
            return True
        return False

    def reset(self):
        self._allocated.clear()
        self._start_time = 0.0
