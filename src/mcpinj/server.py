"""MCP server exposing the sandboxed tools over stdio (official `mcp` Python SDK).

The harness launches one server process per episode:

    MCPINJ_WORLD=world.json MCPINJ_STATE=state.json python -m mcpinj.server

After every tool call the full world state (including the call trace) is
flushed to MCPINJ_STATE, which is what the grader reads.
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from .world import World

mcp = FastMCP("mcp-injection-eval-sandbox", log_level="WARNING")

_WORLD_PATH = os.environ.get("MCPINJ_WORLD")
_STATE_PATH = os.environ.get("MCPINJ_STATE")
WORLD = World.load(_WORLD_PATH) if _WORLD_PATH else World()


def _flush(result: str) -> str:
    if _STATE_PATH:
        WORLD.save(_STATE_PATH)
    return result


@mcp.tool()
def list_files(directory: str = "/home/user") -> str:
    """List files under a directory in the user's workspace."""
    return _flush(WORLD.list_files(directory))


@mcp.tool()
def read_file(path: str) -> str:
    """Read a text file from the user's workspace."""
    return _flush(WORLD.read_file(path))


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Create or overwrite a text file in the user's workspace."""
    return _flush(WORLD.write_file(path, content))


@mcp.tool()
def delete_file(path: str) -> str:
    """Delete a file from the user's workspace."""
    return _flush(WORLD.delete_file(path))


@mcp.tool()
def fetch_webpage(url: str) -> str:
    """Fetch a web page and return its text content."""
    return _flush(WORLD.fetch_webpage(url))


@mcp.tool()
def list_emails() -> str:
    """List emails in the user's inbox (id, sender, subject)."""
    return _flush(WORLD.list_emails())


@mcp.tool()
def read_email(email_id: int) -> str:
    """Read the full body of one email by id."""
    return _flush(WORLD.read_email(email_id))


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email on behalf of the user. `to` may be a comma-separated list."""
    return _flush(WORLD.send_email(to, subject, body))


@mcp.tool()
def run_shell(command: str) -> str:
    """Run a shell command in the user's (sandboxed) workspace."""
    return _flush(WORLD.run_shell(command))


def main() -> None:
    if _STATE_PATH:
        WORLD.save(_STATE_PATH)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
