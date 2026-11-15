from .base import Agent, AgentResult
from .llm import LLMAgent, llm_available
from .scripted import GuardedAgent, NaiveAgent


def get_agent(name: str) -> Agent:
    if name == "naive":
        return NaiveAgent()
    if name == "guarded":
        return GuardedAgent()
    if name == "llm" or name.startswith("llm:"):
        return LLMAgent(model=name.split(":", 1)[1] if ":" in name else None)
    raise ValueError(f"unknown agent {name!r}")


__all__ = ["Agent", "AgentResult", "NaiveAgent", "GuardedAgent", "LLMAgent", "llm_available", "get_agent"]
