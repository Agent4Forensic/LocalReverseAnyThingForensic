"""Gateway contract: the only way the AI reaches a sample.

Implementations: DevGateway (host, pure-Python static tools, this phase) and later the
VM gateway (MCP). Rules that every implementation must keep (PROJEKTPLAN.md 2.3-2.5):
- fixed allowlist of tools, validated arguments, no generic command execution
- sample is data, never started
- path jail, output size limit, timeout
"""
from __future__ import annotations

from typing import Protocol

from sw_analyst.common.models import ToolResult, ToolSpec


DYNAMIC_TOOLS = frozenset({"emulate_function"})    # ADR-0005: offered only with the dashboard switch on and the job's opt-in


class ToolError(Exception):
    """Raised for invalid arguments or jail violations. Message is safe to show to the AI."""


class ToolGateway(Protocol):
    def list_tools(self) -> list[ToolSpec]: ...

    def call(self, job_id: str, name: str, args: dict) -> ToolResult:
        """Run one allowlisted tool. Must never raise for tool-level problems; return ok=False.
        Unknown tool names or invalid arguments return ok=False with an error message."""
        ...

    def sample_path(self, job_id: str) -> str:
        """Jailed path of the job's sample (for display only)."""
        ...

    def list_files(self, job_id: str) -> list[dict]:
        """Sample and derived artifacts: path, kind, size, sha256. Drives artifact recursion in the engine."""
        ...
