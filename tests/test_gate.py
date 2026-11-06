import asyncio
from pathlib import Path

import pytest

from opsgate.gate import Gate
from opsgate.policy import DEFAULT_POLICY, Decision, Policy
from opsgate.store import Store


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def env():
    clock = Clock()
    store = Store(":memory:")
    calls = []

    def deploy(**kw):
        calls.append(kw)
        return {"deployed": kw["tag"]}

    return Gate(DEFAULT_POLICY, store, clock), store, clock, calls, deploy


ARGS = {"service": "api", "tag": "v1.2.0"}


def test_policy_resolution():
    p = Policy(rules={"ecs_*": Decision.ALLOW, "ecs_deploy": Decision.ASK, "ecs_d*": Decision.BLOCK})
    assert p.decide("ecs_deploy") is Decision.ASK
    assert p.decide("ecs_describe") is Decision.BLOCK
    assert p.decide("ecs_tags") is Decision.ALLOW
    assert p.decide("other") is Decision.ASK


def test_destructive_names_blocked_even_if_policy_allows():
    p = Policy(rules={"*": Decision.ALLOW})
    for t in ("ecs_delete_service", "rds_drop", "terminate_instances", "ecs_scale_to_zero"):
        assert p.decide(t) is Decision.BLOCK


def test_policy_loads_from_toml(tmp_path: Path):
    f = tmp_path / "policy.toml"
    f.write_text('default = "block"\napproval_ttl_seconds = 60\n[tools]\n"ecs_tags" = "allow"\n')
    p = Policy.load(f)
    assert p.decide("ecs_tags") is Decision.ALLOW
    assert p.decide("anything") is Decision.BLOCK
    assert p.approval_ttl_seconds == 60


def test_allow_runs_and_audits(env):
    gate, store, _, _, _ = env
    r = gate.call("ecs_tags", {"repository": "api"}, lambda repository: ["v1"])
    assert r == {"status": "ok", "tool": "ecs_tags", "result": ["v1"]}
    assert store.audit()[0]["outcome"] == "ok"


def test_block_never_runs(env):
    gate, store, _, calls, deploy = env
    r = gate.call("ecs_delete_service", ARGS, deploy)
    assert r["status"] == "blocked" and calls == []
    assert store.audit()[0]["outcome"] == "blocked"


def test_ask_full_cycle_and_single_use(env):
    gate, store, _, calls, deploy = env
    r = gate.call("ecs_deploy", ARGS, deploy)
    assert r["status"] == "pending_approval" and calls == []
    aid = r["approval_id"]

    assert gate.call("ecs_deploy", ARGS, deploy, aid)["reason"] == "approval is pending"
    store.decide(aid, True, "alice")
    assert gate.call("ecs_deploy", ARGS, deploy, aid)["status"] == "ok"
    assert calls == [ARGS]
    assert gate.call("ecs_deploy", ARGS, deploy, aid)["reason"] == "approval is used"
    assert len(calls) == 1


def test_approval_bound_to_exact_arguments(env):
    gate, store, _, calls, deploy = env
    aid = gate.call("ecs_deploy", ARGS, deploy)["approval_id"]
    store.decide(aid, True, "alice")
    r = gate.call("ecs_deploy", {**ARGS, "tag": "v9.9.9"}, deploy, aid)
    assert r["status"] == "refused" and "differ" in r["reason"] and calls == []


def test_approval_for_one_tool_cannot_run_another(env):
    gate, store, _, calls, deploy = env
    aid = gate.call("ecs_deploy", ARGS, deploy)["approval_id"]
    store.decide(aid, True, "alice")
    assert gate.call("ecs_revert", ARGS, deploy, aid)["status"] == "refused"


def test_denied_and_expired_fail_closed(env):
    gate, store, clock, calls, deploy = env
    aid = gate.call("ecs_deploy", ARGS, deploy)["approval_id"]
    store.decide(aid, False, "alice")
    assert gate.call("ecs_deploy", ARGS, deploy, aid)["reason"] == "approval is denied"

    aid = gate.call("ecs_deploy", ARGS, deploy)["approval_id"]
    store.decide(aid, True, "alice")
    clock.t += DEFAULT_POLICY.approval_ttl_seconds + 1
    assert "expired" in gate.call("ecs_deploy", ARGS, deploy, aid)["reason"]
    assert calls == []


def test_tool_error_is_reported_and_audited(env):
    gate, store, _, _, _ = env

    def boom(**_):
        e = RuntimeError("tag missing from ECR")
        e.exit_code = 5
        raise e

    r = gate.call("ecs_tags", {}, boom)
    assert r["status"] == "error" and r["exit_code"] == 5
    assert store.audit()[0]["detail"] == "tag missing from ECR"


def test_mcp_server_routes_through_gate(env, monkeypatch):
    from opsgate import server, tools

    gate, _, _, calls, deploy = env
    monkeypatch.setattr(tools, "ecs_deploy", deploy)
    app = server.build(gate)

    async def go():
        listed = {t.name for t in await app.list_tools()}
        assert {"ecs_resolve", "ecs_tags", "ecs_deploy", "ecs_wait", "ecs_revert", "cost_audit"} <= listed
        return await app.call_tool("ecs_deploy", {"service": "api", "repository": "api", "tag": "v1.2.0"})

    out = asyncio.run(go())
    assert "pending_approval" in str(out)
    assert calls == []
