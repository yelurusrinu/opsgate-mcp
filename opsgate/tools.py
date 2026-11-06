from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any


def _session():
    import boto3

    return boto3.Session(profile_name=os.environ.get("OPSGATE_AWS_PROFILE"),
                         region_name=os.environ.get("OPSGATE_AWS_REGION"))


def ecs_resolve(service: str, cluster: str | None = None) -> dict[str, Any]:
    from ecs_safe_deploy.resolve import resolve

    return asdict(resolve(_session().client("ecs"), service, cluster))


def ecs_tags(repository: str, limit: int = 5) -> list[dict[str, Any]]:
    from ecs_safe_deploy.tags import deployable, list_tags

    rows = deployable(list_tags(_session().client("ecr"), repository), limit)
    return [{"tag": t.tag, "kind": t.kind, "pushed_at": t.pushed_at.isoformat()} for t in rows]


def ecs_deploy(service: str, repository: str, tag: str, cluster: str | None = None,
               ticket: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    from ecs_safe_deploy.deploy import deploy
    from ecs_safe_deploy.resolve import resolve

    s = _session()
    ecs, ecr = s.client("ecs"), s.client("ecr")
    return deploy(ecs, ecr, resolve(ecs, service, cluster), repository, tag, ticket=ticket, dry_run=dry_run)


def ecs_wait(service: str, cluster: str | None = None, timeout: float = 600) -> dict[str, Any]:
    from ecs_safe_deploy.resolve import resolve
    from ecs_safe_deploy.watch import wait_stable

    ecs = _session().client("ecs")
    svc = resolve(ecs, service, cluster)
    obs = wait_stable(ecs, svc.cluster, svc.service, timeout)
    return {"verdict": obs.verdict.value, "reason": obs.reason, "tasks_died": obs.deaths}


def ecs_revert(service: str, cluster: str | None = None) -> dict[str, Any]:
    from ecs_safe_deploy.deploy import revert
    from ecs_safe_deploy.resolve import resolve

    ecs = _session().client("ecs")
    return revert(ecs, resolve(ecs, service, cluster))


def cost_audit() -> str:
    from aws_cost_audit.cli import run
    from aws_cost_audit.findings import DEFAULT_RATES

    md, _ = run(os.environ.get("OPSGATE_AWS_PROFILE"), os.environ.get("OPSGATE_AWS_REGION"), DEFAULT_RATES)
    return md
