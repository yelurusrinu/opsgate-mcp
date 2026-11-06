from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Decision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    BLOCK = "block"


ALWAYS_BLOCK = re.compile(r"(^|_)(delete|destroy|terminate|purge|deregister|drop|scale_to_zero)(_|$)")


@dataclass
class Policy:
    rules: dict[str, Decision] = field(default_factory=dict)
    default: Decision = Decision.ASK
    approval_ttl_seconds: int = 1800

    def decide(self, tool: str) -> Decision:
        """Exact name beats glob; longest glob wins. Destructive names are blocked no matter
        what the file says, so a permissive policy edit can't open a delete path."""
        if ALWAYS_BLOCK.search(tool):
            return Decision.BLOCK
        if tool in self.rules:
            return self.rules[tool]
        globs = sorted((p for p in self.rules if any(c in p for c in "*?[")), key=len, reverse=True)
        for pattern in globs:
            if fnmatch.fnmatchcase(tool, pattern):
                return self.rules[pattern]
        return self.default

    @classmethod
    def load(cls, path: Path) -> "Policy":
        data = tomllib.loads(path.read_text())
        return cls(
            rules={k: Decision(v) for k, v in data.get("tools", {}).items()},
            default=Decision(data.get("default", "ask")),
            approval_ttl_seconds=int(data.get("approval_ttl_seconds", 1800)),
        )


DEFAULT_POLICY = Policy(rules={
    "ecs_resolve": Decision.ALLOW,
    "ecs_tags": Decision.ALLOW,
    "ecs_wait": Decision.ALLOW,
    "ecs_deploy_dry_run": Decision.ALLOW,
    "cost_*": Decision.ALLOW,
    "ecs_deploy": Decision.ASK,
    "ecs_revert": Decision.ASK,
})
