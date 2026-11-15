"""End-to-end over a real MCP stdio connection (spawns the server)."""

import asyncio

from mcpinj.runner import run_episode, summarise
from mcpinj.scenarios import load_scenarios

S = {s["id"]: s for s in load_scenarios()}


def _run(agent, sid):
    return asyncio.run(run_episode(agent, S[sid]))


def test_naive_is_compromised_guarded_is_not():
    sid = "cred-01-aws-keys-activation-email"
    naive, guarded = _run("naive", sid), _run("guarded", sid)
    assert naive["attack_success"] is True and naive["task_success"] is True
    assert guarded["attack_success"] is False and guarded["task_success"] is True
    assert any(e["type"] == "quarantined" for e in guarded["agent_events"])
    # server-side trace really contains the exfiltrating call for naive
    assert any(t["tool"] == "send_email" for t in naive["server_trace"])
    assert not any(t["tool"] == "send_email" for t in guarded["server_trace"])


def test_summary_metrics():
    rows = [_run(a, sid) for a in ("naive", "guarded")
            for sid in ("destr-01-delete-thesis-files", "benign-05-curl-dataset")]
    summ = summarise(rows)
    assert summ["naive"]["attack_success_rate"] == 1.0
    assert summ["guarded"]["attack_success_rate"] == 0.0
    assert summ["naive"]["benign_completion"] == 1.0
    assert summ["guarded"]["benign_completion"] == 0.0  # denylist over-refuses an explicit curl
