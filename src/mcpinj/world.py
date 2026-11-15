"""Sandboxed, fully in-memory 'world' that the MCP tools act on.

Nothing here touches the host: the filesystem is a dict, email is a list,
the web is a dict of URL -> page, and the shell is a tiny mock interpreter.
Every tool call is appended to ``trace`` so the grader can audit exactly what
was executed (server-side ground truth, not what the agent *claims* it did).
"""

from __future__ import annotations

import copy
import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

URL_RE = re.compile(r"https?://[^\s'\"`)>]+")


@dataclass
class World:
    files: dict[str, str] = field(default_factory=dict)
    emails: list[dict[str, Any]] = field(default_factory=list)
    web: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    user_email: str = "user@corp.example"
    # --- mutable state recorded during an episode ---
    outbox: list[dict[str, Any]] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    fetch_log: list[str] = field(default_factory=list)
    shell_log: list[str] = field(default_factory=list)
    network_log: list[str] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    initial_files: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------ io
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> World:
        w = cls(
            files=dict(d.get("files", {})),
            emails=[dict(e) for e in d.get("emails", [])],
            web=dict(d.get("web", {})),
            env=dict(d.get("env", {})),
            user_email=d.get("user_email", "user@corp.example"),
        )
        for k in ("outbox", "deleted", "fetch_log", "shell_log", "network_log", "trace"):
            if k in d:
                setattr(w, k, copy.deepcopy(d[k]))
        w.initial_files = dict(d.get("initial_files", w.files))
        return w

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "emails": self.emails,
            "web": self.web,
            "env": self.env,
            "user_email": self.user_email,
            "outbox": self.outbox,
            "deleted": self.deleted,
            "fetch_log": self.fetch_log,
            "shell_log": self.shell_log,
            "network_log": self.network_log,
            "trace": self.trace,
            "initial_files": self.initial_files,
        }

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> World:
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))

    # --------------------------------------------------------------- utils
    @staticmethod
    def _norm(path: str) -> str:
        path = path.strip().strip("'\"")
        if path.startswith("~"):
            path = "/home/user" + path[1:]
        return re.sub(r"/+", "/", path)

    def _log(self, tool: str, args: dict[str, Any], result: str) -> str:
        self.trace.append({"tool": tool, "args": args, "result": result[:2000]})
        return result

    # --------------------------------------------------------------- tools
    def list_files(self, directory: str = "/home/user") -> str:
        d = self._norm(directory).rstrip("/") + "/"
        names = sorted(p for p in self.files if p.startswith(d))
        out = "\n".join(names) if names else f"(no files under {d})"
        return self._log("list_files", {"directory": directory}, out)

    def read_file(self, path: str) -> str:
        p = self._norm(path)
        out = self.files.get(p, f"ERROR: file not found: {p}")
        return self._log("read_file", {"path": path}, out)

    def write_file(self, path: str, content: str) -> str:
        p = self._norm(path)
        self.files[p] = content
        return self._log("write_file", {"path": path, "content": content}, f"wrote {len(content)} bytes to {p}")

    def delete_file(self, path: str) -> str:
        p = self._norm(path)
        if p in self.files:
            del self.files[p]
            self.deleted.append(p)
            out = f"deleted {p}"
        else:
            out = f"ERROR: file not found: {p}"
        return self._log("delete_file", {"path": path}, out)

    def fetch_webpage(self, url: str) -> str:
        self.fetch_log.append(url)
        self.network_log.append(url)
        base = url.split("?", 1)[0]
        out = self.web.get(url) or self.web.get(base) or "404 Not Found"
        return self._log("fetch_webpage", {"url": url}, out)

    def list_emails(self) -> str:
        lines = [f"[{e['id']}] from={e['from']} subject={e['subject']}" for e in self.emails]
        return self._log("list_emails", {}, "\n".join(lines) or "(inbox empty)")

    def read_email(self, email_id: int | str) -> str:
        for e in self.emails:
            if str(e["id"]) == str(email_id):
                out = f"From: {e['from']}\nSubject: {e['subject']}\n\n{e['body']}"
                return self._log("read_email", {"email_id": email_id}, out)
        return self._log("read_email", {"email_id": email_id}, f"ERROR: no email with id {email_id}")

    def send_email(self, to: str, subject: str, body: str) -> str:
        recipients = [r.strip().lower() for r in re.split(r"[,;]", to) if r.strip()]
        self.outbox.append({"to": recipients, "subject": subject, "body": body})
        return self._log("send_email", {"to": to, "subject": subject, "body": body}, f"sent to {', '.join(recipients)}")

    def run_shell(self, command: str) -> str:
        """Mock shell. Never executes anything on the host."""
        self.shell_log.append(command)
        for url in URL_RE.findall(command):
            self.network_log.append(url)
        out = self._mock_shell(command)
        return self._log("run_shell", {"command": command}, out)

    # ----------------------------------------------------------- shell mock
    def _mock_shell(self, command: str) -> str:
        outputs = []
        for part in _split_unquoted(command):
            part = part.strip()
            if not part:
                continue
            outputs.append(self._mock_one(part))
        return "\n".join(o for o in outputs if o) or "(no output)"

    def _mock_one(self, cmd: str) -> str:
        redirect = None
        m = re.match(r"^(.*?)\s*>{1,2}\s*(\S+)$", cmd)
        if m and not cmd.startswith(("python", "curl", "wget")):
            cmd, redirect = m.group(1), self._norm(m.group(2))
        try:
            argv = shlex.split(cmd.split("|")[0])
        except ValueError:
            argv = cmd.split()
        if not argv:
            return ""
        prog, args = argv[0], argv[1:]
        out: str
        if prog == "ls":
            target = self._norm(args[-1]) if args and not args[-1].startswith("-") else "/home/user"
            t = target.rstrip("/") + "/"
            out = "\n".join(sorted(p for p in self.files if p.startswith(t))) or ""
        elif prog == "cat":
            out = "\n".join(self.files.get(self._norm(a), f"cat: {a}: No such file") for a in args)
        elif prog == "rm":
            targets = [self._norm(a) for a in args if not a.startswith("-")]
            removed = []
            for t in targets:
                prefix = t.rstrip("*").rstrip("/")
                for p in list(self.files):
                    if p == t or p.startswith(prefix + "/") or (t.endswith("*") and p.startswith(t[:-1])):
                        del self.files[p]
                        self.deleted.append(p)
                        removed.append(p)
            out = f"removed {len(removed)} file(s)"
        elif prog in ("cp", "mv") and len([a for a in args if not a.startswith("-")]) == 2:
            src, dst = [self._norm(a) for a in args if not a.startswith("-")]
            if src not in self.files:
                return f"{prog}: {src}: No such file"
            self.files[dst] = self.files[src]
            if prog == "mv":
                del self.files[src]
                self.deleted.append(src)
            out = ""
        elif prog == "echo":
            out = " ".join(args)
        elif prog in ("env", "printenv"):
            out = "\n".join(f"{k}={v}" for k, v in self.env.items())
        elif prog in ("curl", "wget"):
            out = "HTTP/1.1 200 OK"
        elif prog.startswith("python"):
            out = "(python exited 0)"
        elif prog in ("pip", "pip3", "make", "pytest", "npm", "git", "mkdir", "touch"):
            out = f"{prog}: ok"
        else:
            out = f"{prog}: command not found"
        if redirect:
            self.files[redirect] = out
            return ""
        return out


def _split_unquoted(command: str) -> list[str]:
    """Split a command line on ;, && and || that are not inside quotes."""
    parts, buf, quote, i = [], [], None, 0
    while i < len(command):
        ch = command[i]
        if quote:
            if ch == quote:
                quote = None
            buf.append(ch)
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch == ";" or command[i:i + 2] in ("&&", "||"):
            parts.append("".join(buf))
            buf = []
            i += 1 if ch == ";" else 2
            continue
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


TOOL_NAMES = [
    "list_files", "read_file", "write_file", "delete_file", "fetch_webpage",
    "list_emails", "read_email", "send_email", "run_shell",
]
SIDE_EFFECT_TOOLS = {"write_file", "delete_file", "send_email", "run_shell"}
