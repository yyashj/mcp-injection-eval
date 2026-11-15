from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class ToolClient(Protocol):
    tools: list[dict[str, Any]]  # name, description, inputSchema

    async def call(self, name: str, args: dict[str, Any]) -> str: ...


@dataclass
class AgentResult:
    final_answer: str
    events: list[dict[str, Any]] = field(default_factory=list)  # agent-side log (incl. blocked calls)


class Agent:
    name = "base"

    async def run(self, client: ToolClient, scenario: dict[str, Any]) -> AgentResult:  # pragma: no cover
        raise NotImplementedError
