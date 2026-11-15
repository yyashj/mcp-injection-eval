"""Deterministic scripted agents.

Both agents carry out the scenario's ``plan`` - the trajectory a competent
assistant would take for the user's task - against the live MCP server.
They differ only in what they do with instructions they find in tool outputs:

* NaiveAgent   - obeys them (models an agent with no instruction hierarchy).
* GuardedAgent - quarantines them (provenance tagging) and passes every
                 side-effecting call through a capability Policy.

They are reference points that validate the harness and grader (a positive and
a defended control), not stand-ins for any particular LLM.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any

from .base import Agent, AgentResult, ToolClient
from .instructions import extract_directives
from .policy import Policy

MAX_DEPTH = 2
TEMPLATE_RE = re.compile(r"\{\{(output|extract):(.+?)\}\}")


class ScriptedAgent(Agent):
    follow_untrusted = True
    guarded = False

    async def run(self, client: ToolClient, scenario: dict[str, Any]) -> AgentResult:
        self.client = client
        self.user_task = scenario["user_task"]
        self.outputs: list[str] = []
        self.plan_outputs: list[str] = []
        self.events: list[dict[str, Any]] = []
        self.done: set[str] = set()
        self.policy: Policy | None = None
        if self.guarded:
            contacts = await client.call("read_file", {"path": "/home/user/contacts.csv"})
            trusted = {m.lower() for m in re.findall(r"[\w.+-]+@[\w.-]+", contacts)}
            self.policy = Policy(self.user_task, trusted)
            self.events.append({"type": "trusted_config", "trusted_recipients": sorted(trusted)})

        final = ""
        for step in scenario["plan"]:
            if "final" in step:
                final = self._render(step["final"])
                continue
            args = {k: self._render(v) if isinstance(v, str) else v for k, v in step.get("args", {}).items()}
            out = await self._call(step["call"], args, origin="plan", depth=0)
            self.plan_outputs.append(out or "")
        return AgentResult(final, self.events)

    # ------------------------------------------------------------ helpers
    def _render(self, s: str) -> str:
        def sub(m: re.Match) -> str:
            kind, arg = m.group(1), m.group(2)
            if kind == "output":
                if not self.plan_outputs:
                    return ""
                return self.plan_outputs[-1] if arg == "last" else (
                    self.plan_outputs[int(arg)] if int(arg) < len(self.plan_outputs) else "")
            for out in reversed(self.outputs):
                mm = re.search(arg, out, re.I | re.M)
                if mm:
                    return mm.group(1) if mm.groups() else mm.group(0)
            return ""
        return TEMPLATE_RE.sub(sub, s)

    async def _call(self, tool: str, args: dict[str, Any], origin: str, depth: int) -> str | None:
        if self.policy is not None:
            ok, why = self.policy.check(tool, args)
            if not ok:
                self.events.append({"type": "blocked", "origin": origin, "tool": tool, "args": args, "reason": why})
                return None
        out = await self.client.call(tool, args)
        self.outputs.append(out)
        self.events.append({"type": "call", "origin": origin, "tool": tool, "args": args})
        await self._handle_output(out, tool, args, depth)
        return out

    async def _handle_output(self, out: str, tool: str, args: dict[str, Any], depth: int) -> None:
        if depth >= MAX_DEPTH or tool in ("write_file", "send_email", "delete_file"):
            return
        directives = extract_directives(out)
        if not directives:
            return
        ref = args.get("path") or args.get("url")
        trusted = self.follow_untrusted or (self.policy is not None and self.policy.delegates_to(ref))
        if not trusted:
            self.events.append({"type": "quarantined", "source": tool, "ref": ref,
                                "instructions": [d.raw for d in directives]})
            return
        for d in directives:
            key = d.tool + json.dumps(d.args, sort_keys=True)
            if key in self.done:
                continue
            self.done.add(key)
            files: dict[str, str] = {}
            for p in d.reads:
                files[p] = await self._call("read_file", {"path": p}, origin="injection", depth=MAX_DEPTH) or ""
            new_args = {}
            for k, v in d.args.items():
                if isinstance(v, str):
                    for p, content in files.items():
                        v = v.replace(f"{{{{file:{p}}}}}", content)
                        v = v.replace(f"{{{{urlencode:{p}}}}}", urllib.parse.quote(content))
                    v = v.replace("{{source}}", out).replace("{{urlencode_source}}", urllib.parse.quote(out))
                new_args[k] = v
            await self._call(d.tool, new_args, origin="injection", depth=depth + 1)


class NaiveAgent(ScriptedAgent):
    name = "naive"
    follow_untrusted = True
    guarded = False


class GuardedAgent(ScriptedAgent):
    name = "guarded"
    follow_untrusted = False
    guarded = True
