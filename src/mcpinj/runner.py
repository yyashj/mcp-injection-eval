"""Run agents over all scenarios through a real MCP stdio connection and grade them.

    python -m mcpinj.runner --agents naive,guarded [--out results]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .agents import get_agent, llm_available
from .grader import grade
from .scenarios import load_scenarios
from .world import World

SRC_DIR = str(Path(__file__).resolve().parents[1])


class MCPToolClient:
    def __init__(self, session: ClientSession, tools: list[dict[str, Any]]):
        self.session = session
        self.tools = tools

    async def call(self, name: str, args: dict[str, Any]) -> str:
        res = await self.session.call_tool(name, args)
        text = "\n".join(getattr(c, "text", "") for c in res.content)
        return ("ERROR: " + text) if res.isError else text


async def run_episode(agent_name: str, scenario: dict[str, Any]) -> dict[str, Any]:
    agent = get_agent(agent_name)
    with tempfile.TemporaryDirectory() as td:
        world_path, state_path = os.path.join(td, "world.json"), os.path.join(td, "state.json")
        World.from_dict(scenario["world_resolved"]).save(world_path)
        env = dict(os.environ, MCPINJ_WORLD=world_path, MCPINJ_STATE=state_path,
                   PYTHONPATH=SRC_DIR + os.pathsep + os.environ.get("PYTHONPATH", ""))
        params = StdioServerParameters(command=sys.executable, args=["-m", "mcpinj.server"], env=env)
        t0 = time.perf_counter()
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                tools = [{"name": t.name, "description": t.description or "", "inputSchema": t.inputSchema}
                         for t in listed.tools]
                result = await agent.run(MCPToolClient(session, tools), scenario)
        state = World.load(state_path)
    g = grade(scenario, state, result.final_answer)
    return {
        "agent": agent.name, **asdict(g), "final_answer": result.final_answer,
        "agent_events": result.events, "server_trace": state.trace,
        "seconds": round(time.perf_counter() - t0, 3),
    }


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    by_agent: dict[str, list] = defaultdict(list)
    for r in rows:
        by_agent[r["agent"]].append(r)
    for agent, rs in by_agent.items():
        attacks = [r for r in rs if r["is_attack"]]
        benign = [r for r in rs if not r["is_attack"]]
        cats: dict[str, list] = defaultdict(list)
        for r in attacks:
            cats[r["category"]].append(r)
        out[agent] = {
            "n_attack": len(attacks),
            "n_benign": len(benign),
            "attack_success_rate": _rate(sum(r["attack_success"] for r in attacks), len(attacks)),
            "attacks_succeeded": sum(r["attack_success"] for r in attacks),
            "utility_under_attack": _rate(sum(r["task_success"] for r in attacks), len(attacks)),
            "benign_completion": _rate(sum(r["task_success"] for r in benign), len(benign)),
            "benign_completed": sum(r["task_success"] for r in benign),
            "per_category": {c: {"n": len(v), "succeeded": sum(r["attack_success"] for r in v),
                                 "asr": _rate(sum(r["attack_success"] for r in v), len(v))}
                             for c, v in sorted(cats.items())},
        }
    return out


def _rate(a: int, b: int) -> float:
    return round(a / b, 4) if b else 0.0


def to_markdown(summary: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    agents = list(summary)
    pct = lambda x: f"{100 * x:.1f}%"  # noqa: E731
    lines = ["# Results", "", "| Metric | " + " | ".join(agents) + " |", "|---|" + "---|" * len(agents)]
    lines.append("| Attack success rate (ASR) ↓ | " + " | ".join(
        f"{pct(summary[a]['attack_success_rate'])} ({summary[a]['attacks_succeeded']}/{summary[a]['n_attack']})"
        for a in agents) + " |")
    lines.append("| Benign task completion ↑ | " + " | ".join(
        f"{pct(summary[a]['benign_completion'])} ({summary[a]['benign_completed']}/{summary[a]['n_benign']})"
        for a in agents) + " |")
    lines.append("| Utility under attack ↑ | " + " | ".join(
        pct(summary[a]["utility_under_attack"]) for a in agents) + " |")
    cats = sorted({c for a in agents for c in summary[a]["per_category"]})
    lines += ["", "## ASR by attack category", "", "| Category | n | " + " | ".join(agents) + " |",
              "|---|---|" + "---|" * len(agents)]
    for c in cats:
        n = summary[agents[0]]["per_category"].get(c, {}).get("n", 0)
        lines.append(f"| {c} | {n} | " + " | ".join(
            "{}/{}".format(summary[a]["per_category"].get(c, {}).get("succeeded", 0), n) for a in agents) + " |")
    lines += ["", "## Per-scenario", "", "| Scenario | Category | " + " | ".join(
        f"{a} attack / task" for a in agents) + " |", "|---|---|" + "---|" * len(agents)]
    idx = {(r["agent"], r["scenario_id"]): r for r in rows}
    for sid, cat in dict.fromkeys((r["scenario_id"], r["category"]) for r in rows):
        cells = []
        for a in agents:
            r = idx.get((a, sid))
            att = "—" if r["attack_success"] is None else ("HIT" if r["attack_success"] else "safe")
            cells.append(f"{att} / {'done' if r['task_success'] else 'fail'}")
        lines.append(f"| {sid} | {cat} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


async def main_async(args: argparse.Namespace) -> dict[str, Any]:
    scenarios = load_scenarios(args.scenarios)
    if args.filter:
        scenarios = [s for s in scenarios if args.filter in s["id"]]
    agents = [a.strip() for a in args.agents.split(",") if a.strip()]
    if any(a.startswith("llm") for a in agents) and not llm_available():
        print("[skip] OPENAI_API_KEY not set - skipping LLM agent", file=sys.stderr)
        agents = [a for a in agents if not a.startswith("llm")]
    rows = []
    for a in agents:
        for s in scenarios:
            r = await run_episode(a, s)
            rows.append(r)
            mark = "" if r["attack_success"] is None else (" ATTACK-HIT" if r["attack_success"] else " safe")
            print(f"[{r['agent']:>8}] {s['id']:<40} task={'ok ' if r['task_success'] else 'FAIL'}{mark}")
    summary = summarise(rows)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps({"summary": summary, "episodes": rows}, indent=2))
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    md = to_markdown(summary, rows)
    (out / "results.md").write_text(md)
    print("\n" + md)
    return summary


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--agents", default=os.environ.get("MCPINJ_AGENTS", "naive,guarded,llm"))
    p.add_argument("--scenarios", default=None, help="directory of scenario YAML files")
    p.add_argument("--out", default="results")
    p.add_argument("--filter", default=None, help="only run scenario ids containing this string")
    asyncio.run(main_async(p.parse_args()))


if __name__ == "__main__":
    main()
