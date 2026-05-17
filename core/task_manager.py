"""
Task Manager Module
===================
Manages async task queues, concurrency control,
scan state persistence, and resume functionality.
"""

import asyncio
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Callable, Optional
from pathlib import Path


class TaskManager:
    """
    Manages async tasks with concurrency limits and state persistence.
    Supports scan resume on interruption.
    """

    def __init__(self, config: Dict, logger, state_file: str = ".scan_state.json"):
        self.config = config
        self.logger = logger
        self.state_file = state_file
        self.max_concurrent = config["scan"].get("threads", 10)
        self.completed_tasks: set = set()
        self.failed_tasks: set = set()
        self._load_state()

    def _load_state(self):
        """Load saved scan state for resume support."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    state = json.load(f)
                self.completed_tasks = set(state.get("completed", []))
                self.logger.info(f"Resumed scan: {len(self.completed_tasks)} tasks already completed")
            except Exception:
                pass

    def _save_state(self):
        """Persist current scan state."""
        try:
            with open(self.state_file, "w") as f:
                json.dump({
                    "completed": list(self.completed_tasks),
                    "timestamp": datetime.now().isoformat(),
                }, f)
        except Exception:
            pass

    def is_completed(self, task_id: str) -> bool:
        """Check if a task was already completed (for resume)."""
        return task_id in self.completed_tasks

    def mark_completed(self, task_id: str):
        """Mark a task as completed and persist state."""
        self.completed_tasks.add(task_id)
        self._save_state()

    def clear_state(self):
        """Clear saved scan state (fresh scan)."""
        self.completed_tasks.clear()
        self.failed_tasks.clear()
        if os.path.exists(self.state_file):
            os.remove(self.state_file)

    async def run_batch(self, tasks: List[Callable], task_ids: Optional[List[str]] = None) -> List[Any]:
        """
        Run a batch of async tasks with concurrency control.

        Args:
            tasks: List of async callables
            task_ids: Optional list of task IDs for resume support

        Returns:
            List of task results
        """
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def run_one(task_fn: Callable, task_id: Optional[str]) -> Any:
            # Skip if already completed (resume mode)
            if task_id and self.is_completed(task_id):
                self.logger.debug(f"Skipping completed task: {task_id}")
                return None

            async with semaphore:
                try:
                    result = await task_fn()
                    if task_id:
                        self.mark_completed(task_id)
                    return result
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self.logger.error(f"Task failed: {e}")
                    if task_id:
                        self.failed_tasks.add(task_id)
                    return None

        if task_ids:
            coroutines = [run_one(task, tid) for task, tid in zip(tasks, task_ids)]
        else:
            coroutines = [run_one(task, None) for task in tasks]

        results = await asyncio.gather(*coroutines, return_exceptions=True)
        return [r for r in results if r is not None and not isinstance(r, Exception)]

    def get_stats(self) -> Dict[str, int]:
        """Return task execution statistics."""
        return {
            "completed": len(self.completed_tasks),
            "failed": len(self.failed_tasks),
        }
