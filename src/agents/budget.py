"""Turn / token / wall-clock budget for one agent run.

A turn is one LLM call. The engine checks ``exceeded()`` before every call, so a
run stops cleanly (status BUDGET_EXCEEDED) instead of raising mid-tool.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

from llm.provider import Usage


class BudgetLimits(BaseModel):
    max_turns: int = Field(default=40, ge=1)
    max_input_tokens: int | None = Field(default=None, ge=1)
    max_output_tokens: int | None = Field(default=None, ge=1)
    max_total_tokens: int | None = Field(default=1_000_000, ge=1)
    max_wall_seconds: float | None = Field(default=None, gt=0)


class Budget:
    def __init__(self, limits: BudgetLimits | None = None, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.limits = limits or BudgetLimits()
        self._clock = clock
        self._started = clock()
        self.turns = 0
        self.usage = Usage()

    def charge(self, usage: Usage) -> None:
        """Record one completed LLM call."""
        self.turns += 1
        self.usage = Usage(
            input_tokens=self.usage.input_tokens + usage.input_tokens,
            output_tokens=self.usage.output_tokens + usage.output_tokens,
        )

    @property
    def elapsed(self) -> float:
        return self._clock() - self._started

    def exceeded(self) -> str | None:
        """Why the NEXT turn is not allowed, or None if it is."""
        lim, u = self.limits, self.usage
        if self.turns >= lim.max_turns:
            return f"turn limit reached ({self.turns}/{lim.max_turns})"
        if lim.max_input_tokens is not None and u.input_tokens >= lim.max_input_tokens:
            return f"input token limit reached ({u.input_tokens}/{lim.max_input_tokens})"
        if lim.max_output_tokens is not None and u.output_tokens >= lim.max_output_tokens:
            return f"output token limit reached ({u.output_tokens}/{lim.max_output_tokens})"
        if lim.max_total_tokens is not None and u.total_tokens >= lim.max_total_tokens:
            return f"total token limit reached ({u.total_tokens}/{lim.max_total_tokens})"
        if lim.max_wall_seconds is not None and self.elapsed >= lim.max_wall_seconds:
            return f"wall-clock limit reached ({self.elapsed:.0f}s/{lim.max_wall_seconds:.0f}s)"
        return None

    def cap_max_tokens(self, requested: int) -> int:
        """Shrink a turn's max_tokens so it can't overshoot the output budget."""
        caps = [requested]
        if self.limits.max_output_tokens is not None:
            caps.append(self.limits.max_output_tokens - self.usage.output_tokens)
        if self.limits.max_total_tokens is not None:
            caps.append(self.limits.max_total_tokens - self.usage.total_tokens)
        return max(1, min(caps))

    def snapshot(self) -> dict[str, Any]:
        return {
            "turns": self.turns,
            "max_turns": self.limits.max_turns,
            "input_tokens": self.usage.input_tokens,
            "output_tokens": self.usage.output_tokens,
            "total_tokens": self.usage.total_tokens,
            "elapsed_seconds": round(self.elapsed, 3),
        }
