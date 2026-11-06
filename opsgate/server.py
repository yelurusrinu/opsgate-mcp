from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from . import tools
from .gate import Gate

INSTRUCTIONS = """\
Every tool goes through a policy gate. A result with status "pending_approval" means a human
must approve it out of band; tell the user the approval id and stop. When they confirm, call the
same tool again with identical arguments plus approval_id. Never change arguments after approval,
never retry a "blocked" tool, and report "refused" verbatim.

For a deploy: ecs_resolve → ecs_tags → ecs_deploy(dry_run=True) → ecs_deploy (approval) →
ecs_wait. On verdict FAIL, call ecs_revert (approval). DEGRADED and BLOCKED are not PASS.
"""


def build(gate: Gate) -> MCPServer:
    app = MCPServer(name="opsgate", instructions=INSTRUCTIONS)

    @app.tool(description="Find the real ECS cluster and service by discovery. Read-only.")
    def ecs_resolve(service: str, cluster: str | None = None) -> dict[str, Any]:
        return gate.call("ecs_resolve", {"service": service, "cluster": cluster}, tools.ecs_resolve)

    @app.tool(description="Newest deployable image tags for an ECR repository. Read-only.")
    def ecs_tags(repository: str, limit: int = 5) -> dict[str, Any]:
        return gate.call("ecs_tags", {"repository": repository, "limit": limit}, tools.ecs_tags)

    @app.tool(description="Snapshot, then blue/green deploy an image tag to an ECS service. Needs approval.")
    def ecs_deploy(service: str, repository: str, tag: str, cluster: str | None = None,
                   ticket: str | None = None, dry_run: bool = False,
                   approval_id: str | None = None) -> dict[str, Any]:
        args = {"service": service, "repository": repository, "tag": tag,
                "cluster": cluster, "ticket": ticket, "dry_run": dry_run}
        if dry_run:
            return gate.call("ecs_deploy_dry_run", args, tools.ecs_deploy)
        return gate.call("ecs_deploy", args, tools.ecs_deploy, approval_id)

    @app.tool(description="Block until the rollout is PASS, DEGRADED, FAIL or BLOCKED. Read-only.")
    def ecs_wait(service: str, cluster: str | None = None, timeout: float = 600) -> dict[str, Any]:
        return gate.call("ecs_wait", {"service": service, "cluster": cluster, "timeout": timeout}, tools.ecs_wait)

    @app.tool(description="Point the service back at its pre-deploy snapshot. Needs approval.")
    def ecs_revert(service: str, cluster: str | None = None, approval_id: str | None = None) -> dict[str, Any]:
        return gate.call("ecs_revert", {"service": service, "cluster": cluster}, tools.ecs_revert, approval_id)

    @app.tool(description="Read-only AWS cost audit: baseline, idle resources, tiered savings plan.")
    def cost_audit() -> dict[str, Any]:
        return gate.call("cost_audit", {}, tools.cost_audit)

    return app
