"""Shared, LLM-agnostic data shapes: used by the standalone engine AND the MCP server."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ToolSpec(BaseModel):
    """A tool the model may call. ``input_schema`` is a JSON Schema object."""

    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})


class ToolResult(BaseModel):
    content: str
    is_error: bool = False
    data: dict[str, Any] = Field(default_factory=dict)
