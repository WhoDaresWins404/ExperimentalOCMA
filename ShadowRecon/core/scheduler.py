from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

from .models import ScanProfile, Directive, ScanTarget
from .budget import TimeBudgetManager
from .directive import DirectiveBus
from .config import ScanConfig
from scanners.base import BaseScanner
from core.exceptions import ScanCancelled


@dataclass(order=True)
class ScannerJob:
    priority: int
    name: str = field(compare=False)
    scanner: BaseScanner = field(compare=False)
    dependencies: list[str] = field(default_factory=list, compare=False)
    time_budget: int = field(default=120, compare=False)


class PriorityScheduler:
    """Replaces the fixed _run_scanners() — a priority queue with dynamic reordering."""

    def __init__(
        self,
        scanners: dict[str, BaseScanner],
        budget_mgr: TimeBudgetManager,
        directive_bus: DirectiveBus,
        config: ScanConfig,
    ):
        self._scanners = scanners
        self._budget = budget_mgr
        self._bus = directive_bus
        self._config = config
        self._queue: list[ScannerJob] = []
        self._completed: set[str] = set()
        self._cancelled = False

    def build_from_profile(self, profile: ScanProfile, mode: str):
        """Build initial queue from scan profile and mode."""
        if mode == "light":
            order = ["crawler_scanner", "directory_scanner", "misconfig_scanner"]
        elif mode == "waf_only":
            order = []
        else:
            order = ["crawler_scanner", "api_scanner", "directory_scanner",
                     "misconfig_scanner", "anomaly_detector", "form_scanner"]

        for name in order:
            if name not in self._scanners:
                continue

            if name in profile.skipped_scanners:
                continue

            base_priority = profile.scanner_priorities.get(name, 50)

            job = ScannerJob(
                priority=base_priority,
                name=name,
                scanner=self._scanners[name],
                time_budget=self._budget.allocate(name, weight=0.15),
            )
            self._queue.append(job)

        self._queue.sort(key=lambda j: j.priority)

    async def run_next(self, target: ScanTarget) -> Optional[tuple[str, tuple]]:
        """Dequeue and run the next available scanner. Returns (name, results) or None."""
        if self._cancelled:
            raise ScanCancelled()

        while self._queue:
            job = self._queue.pop(0)

            if job.name in self._completed:
                continue

            # Check dependencies
            deps_met = all(dep in self._completed for dep in job.dependencies)
            if not deps_met and job.dependencies:
                self._queue.append(job)
                continue

            # Check skip directive
            skip_dirs = await self._bus.consume(job.name)
            if any(d.action == "skip" for d in skip_dirs):
                self._completed.add(job.name)
                continue
            # Re-issue non-skip directives
            if skip_dirs:
                non_skip = [d for d in skip_dirs if d.action != "skip"]
                if non_skip:
                    await self._bus.issue_many(non_skip)

            # Apply directives to scanner
            scanner = job.scanner
            consume = await self._bus.consume(scanner.name)
            for d in consume:
                if d.action == "augment_wordlist" and isinstance(d.payload, list):
                    if hasattr(scanner, "_augmented_paths"):
                        scanner._augmented_paths = (scanner._augmented_paths or []) + d.payload
                    else:
                        scanner._augmented_paths = d.payload
                elif d.action == "adjust_param" and isinstance(d.payload, dict):
                    for k, v in d.payload.items():
                        if hasattr(scanner.config, k):
                            setattr(scanner.config, k, v)
                        elif k == "evasion_headers" and hasattr(scanner, "waf_state"):
                            scanner.waf_state.update(v)

            try:
                findings, endpoints = await asyncio.wait_for(
                    scanner.scan(target),
                    timeout=job.time_budget,
                )
                self._completed.add(job.name)
                self._budget.surplus(job.name, job.time_budget)
            except asyncio.TimeoutError:
                findings, endpoints = [], []
                self._completed.add(job.name)
                self._budget.surplus(job.name, job.time_budget)
            except Exception:
                findings, endpoints = [], []
                self._completed.add(job.name)
            finally:
                await scanner.cleanup()

            return job.name, (findings, endpoints)

        return None

    async def reprioritize(self, scanner_name: str, new_priority: int):
        """Move a scanner up/down in the queue."""
        for job in self._queue:
            if job.name == scanner_name and job.name not in self._completed:
                job.priority = new_priority
        self._queue.sort(key=lambda j: j.priority)

    async def grant_emergency_time(self, scanner_name: str, amount: int) -> bool:
        for job in self._queue:
            if job.name == scanner_name and job.name not in self._completed:
                return self._budget.emergency_fund(scanner_name, amount)
        return False

    def cancel(self):
        self._cancelled = True

    @property
    def completed(self) -> list[str]:
        return list(self._completed)

    @property
    def pending(self) -> list[str]:
        return [j.name for j in self._queue if j.name not in self._completed]
