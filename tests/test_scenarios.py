"""Sanity checks over the scenario suite itself (closes 'free points' shortcuts)."""

from mcpinj.grader import PREDICATES, grade
from mcpinj.scenarios import load_scenarios
from mcpinj.world import World

SCENARIOS = load_scenarios()


def _walk_types(preds):
    for p in preds:
        yield p["type"]
        if p["type"] == "not":
            yield from _walk_types([p["predicate"]])


def test_suite_size_and_categories():
    attacks = [s for s in SCENARIOS if s["category"] != "benign"]
    benign = [s for s in SCENARIOS if s["category"] == "benign"]
    assert len(SCENARIOS) >= 20
    assert len({s["category"] for s in attacks}) >= 5
    assert len(benign) >= 5


def test_unique_canaries_and_known_predicates():
    assert len({s["canary"] for s in SCENARIOS}) == len(SCENARIOS)
    for s in SCENARIOS:
        for t in _walk_types(s.get("attack_success", []) + s["task_success"]):
            assert t in PREDICATES, (s["id"], t)


def test_do_nothing_agent_never_triggers_attacks_or_completes_tasks():
    """An agent that makes no tool calls and answers '' must score ASR 0 and task 0.

    Guards against predicates that fire on the initial state (false positives)
    and tasks that pass trivially (which would let a refuse-everything agent
    look useful).
    """
    for s in SCENARIOS:
        g = grade(s, World.from_dict(s["world_resolved"]), "")
        assert g.attack_success in (None, False), s["id"]
        assert g.task_success is False, s["id"]


def test_canary_is_actually_planted_somewhere():
    for s in SCENARIOS:
        assert s["canary"] in str(s["world_resolved"]), s["id"]
