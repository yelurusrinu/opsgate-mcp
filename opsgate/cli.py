from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from .policy import DEFAULT_POLICY, Policy
from .store import Store

HOME = Path(os.environ.get("OPSGATE_HOME", Path.home() / ".opsgate"))


def _store() -> Store:
    return Store(HOME / "opsgate.db")


def _policy(path: Path | None) -> Policy:
    path = path or HOME / "policy.toml"
    return Policy.load(path) if path.exists() else DEFAULT_POLICY


def _ts(t: float | None) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S") if t else "-"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="opsgate", description="Policy-gated MCP server for infra agents.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the MCP server over stdio")
    s.add_argument("--policy", type=Path)

    sub.add_parser("pending", help="list approvals waiting on a human")

    for name in ("approve", "deny"):
        s = sub.add_parser(name)
        s.add_argument("id")

    s = sub.add_parser("log", help="show the audit log")
    s.add_argument("-n", type=int, default=20)

    s = sub.add_parser("policy", help="show what each tool resolves to")
    s.add_argument("--policy", type=Path)

    a = p.parse_args(argv)

    if a.cmd == "serve":
        from .gate import Gate
        from .server import build

        build(Gate(_policy(a.policy), _store())).run("stdio")
        return 0

    store = _store()
    if a.cmd == "pending":
        rows = store.pending()
        if not rows:
            print("nothing pending")
        for r in rows:
            print(f"{r.id}  {_ts(r.created_at)}  {r.tool}\n          {json.dumps(r.args)}")
        return 0

    if a.cmd in ("approve", "deny"):
        r = store.get(a.id)
        if r is None:
            print(f"no approval {a.id}", file=sys.stderr)
            return 1
        print(f"{r.tool}  {json.dumps(r.args, indent=2)}")
        try:
            r = store.decide(a.id, a.cmd == "approve", getpass.getuser())
        except ValueError as e:
            print(e, file=sys.stderr)
            return 1
        print(f"{r.status} by {r.decided_by}")
        return 0

    if a.cmd == "log":
        for e in reversed(store.audit(a.n)):
            print(f"{_ts(e['ts'])}  {e['tool']:<20} {e['decision']:<6} {e['outcome']:<16} "
                  f"{e['approval_id'] or '':<9} {e['detail'] or ''}")
        return 0

    if a.cmd == "policy":
        pol = _policy(a.policy)
        for t in ("ecs_resolve", "ecs_tags", "ecs_wait", "cost_audit", "ecs_deploy_dry_run",
                  "ecs_deploy", "ecs_revert", "ecs_delete_service"):
            print(f"  {t:<22} {pol.decide(t).value}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
