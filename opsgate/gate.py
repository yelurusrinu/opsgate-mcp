from __future__ import annotations

import time
from typing import Any, Callable

from .policy import Decision, Policy
from .store import Store, args_hash


class Gate:
    def __init__(self, policy: Policy, store: Store, clock: Callable[[], float] = time.time):
        self.policy = policy
        self.store = store
        self.clock = clock

    def call(self, tool: str, args: dict[str, Any], fn: Callable[..., Any],
             approval_id: str | None = None) -> dict[str, Any]:
        decision = self.policy.decide(tool)

        if decision is Decision.BLOCK:
            self.store.log(tool, args, decision.value, "blocked")
            return {"status": "blocked", "tool": tool, "reason": "policy blocks this tool"}

        if decision is Decision.ASK:
            refusal = self._check_approval(tool, args, approval_id)
            if refusal is not None:
                return refusal

        started = self.clock()
        try:
            result = fn(**args)
        except Exception as e:
            self.store.log(tool, args, decision.value, "error", approval_id, str(e),
                           int((self.clock() - started) * 1000))
            return {"status": "error", "tool": tool, "error": str(e),
                    "exit_code": getattr(e, "exit_code", None)}
        self.store.log(tool, args, decision.value, "ok", approval_id, None, int((self.clock() - started) * 1000))
        return {"status": "ok", "tool": tool, "result": result}

    def _check_approval(self, tool: str, args: dict[str, Any], approval_id: str | None) -> dict | None:
        if not approval_id:
            a = self.store.request(tool, args, self.clock())
            self.store.log(tool, args, "ask", "pending", a.id)
            return {
                "status": "pending_approval",
                "approval_id": a.id,
                "message": f"A human must run `opsgate approve {a.id}`. Then call {tool} again with "
                           f"the same arguments and approval_id='{a.id}'. Do not change the arguments.",
                "expires_in_seconds": self.policy.approval_ttl_seconds,
            }

        a = self.store.get(approval_id)
        why = None
        if a is None:
            why = "unknown approval id"
        elif a.args_hash != args_hash(tool, args):
            why = "arguments differ from what was approved"
        elif self.clock() - a.created_at > self.policy.approval_ttl_seconds:
            self.store.expire(a.id)
            why = "approval expired; no reply is not consent — request again"
        elif a.status != "approved":
            why = f"approval is {a.status}"
        elif not self.store.consume(a.id, self.clock()):
            why = "approval already used"

        if why:
            self.store.log(tool, args, "ask", "refused", approval_id, why)
            return {"status": "refused", "tool": tool, "approval_id": approval_id, "reason": why}
        return None
