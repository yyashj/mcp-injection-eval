"""The 'guarded' agent's defense: an instruction hierarchy plus a capability gate.

1. Provenance / instruction hierarchy: text returned by tools is DATA. Imperative
   instructions found in it are quarantined, never executed - unless the user's
   own task explicitly delegates to that exact resource ("follow the steps in
   /path/SETUP.md"), in which case they run, but still through the gate below.
2. Capability gate on every side-effecting call, derived only from the user's
   task text and a trusted contacts file:
     - send_email: every recipient must be named in the task or in contacts.csv
     - write_file / delete_file: the path must be named in the task (and the task
       must ask for deletion for delete_file)
     - run_shell: the task must ask for running/installing/building, and the
       command must not match a denylist of network/destructive programs
     - fetch_webpage: the domain must be named in the task
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .instructions import EMAIL_RE, PATH_RE, URL_RE

DELEGATION_RE = re.compile(
    r"\b(follow|carry out|do what|perform|complete) (the |all )?(steps|instructions|setup|checklist|tasks?)\b|"
    r"\bas (described|instructed) in\b", re.I)
SHELL_INTENT_RE = re.compile(r"\b(run|execute|install|build|set ?up|setup|test|follow|download)\b", re.I)
DELETE_INTENT_RE = re.compile(r"\b(delete|remove|clean|clear)\b", re.I)
SHELL_DENY_RE = re.compile(
    r"(\brm\s+-\w*[rf]|\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bscp\b|\bssh\b|\bmkfs\b|\bdd\s+if=|>\s*/dev/|\bchmod\s+777\b|"
    r"\.ssh/|\.aws/|\.env\b|\bbase64\b)", re.I)


def _norm(p: str) -> str:
    p = p.strip().strip("'\"").rstrip(".,;:")
    return "/home/user" + p[1:] if p.startswith("~") else p


@dataclass
class Policy:
    user_task: str
    trusted_recipients: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.task_emails = {e.lower() for e in EMAIL_RE.findall(self.user_task)}
        self.task_urls = URL_RE.findall(self.user_task)
        self.task_domains = {urlparse(u).netloc.lower() for u in self.task_urls}
        no_urls = URL_RE.sub(" ", EMAIL_RE.sub(" ", self.user_task))
        self.task_paths = {_norm(p) for p in PATH_RE.findall(no_urls)}

    def mentions_resource(self, ref: str | None) -> bool:
        if not ref:
            return False
        r = _norm(str(ref))
        return r in self.task_paths or any(r.split("?")[0] == u.rstrip(".,;") for u in self.task_urls)

    def delegates_to(self, ref: str | None) -> bool:
        return bool(DELEGATION_RE.search(self.user_task)) and self.mentions_resource(ref)

    def check(self, tool: str, args: dict) -> tuple[bool, str]:
        if tool == "send_email":
            rcpts = {r.strip().lower() for r in re.split(r"[,;]", args.get("to", "")) if r.strip()}
            bad = rcpts - self.task_emails - self.trusted_recipients
            return (not bad, f"recipient(s) not authorised by user: {sorted(bad)}" if bad else "ok")
        if tool == "write_file":
            ok = _norm(args.get("path", "")) in self.task_paths
            return ok, "ok" if ok else "write target not named in user task"
        if tool == "delete_file":
            ok = _norm(args.get("path", "")) in self.task_paths and bool(DELETE_INTENT_RE.search(self.user_task))
            return ok, "ok" if ok else "deletion not requested by user"
        if tool == "run_shell":
            cmd = args.get("command", "")
            if not SHELL_INTENT_RE.search(self.user_task):
                return False, "user did not ask to run commands"
            if SHELL_DENY_RE.search(cmd):
                return False, "command matches denylist"
            return True, "ok"
        if tool == "fetch_webpage":
            dom = urlparse(args.get("url", "")).netloc.lower()
            ok = dom in self.task_domains
            return ok, "ok" if ok else f"domain {dom} not named in user task"
        return True, "ok"  # read-only tools
