"""Policy gateway: a checkpoint between the agent and its tools.

The agent's model can be talked into anything, so the gateway does not ask
the model's opinion. It enforces four rules outside the model:

  1. Task allowlist      only tools the current task needs can be called.
  2. Human approval      public writes and destructive actions need a human
                         to say yes.
  3. Resource limits     an allowed tool may only be used on the resources
                         the task names (for example one specific note).
  4. Data-flow rule      private data must not reach a public place without
                         a human approving that specific flow. A flow is
                         either a public write after a private read in the
                         same session, or a single tool labelled
                         "private_to_public" that does both on the server.

`composite_aware=False` reproduces the first version of rule 4, kept for
comparison: it only watched for read-then-write at the agent boundary, hard
blocked it, and so missed tools that copy private data server-side.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .servers.base import Tool

PUBLIC_CLASSES = {"public_write", "private_to_public"}
APPROVAL_CLASSES = {"public_write", "private_to_public", "destructive"}


def deny_all(qualified_name: str, args: dict) -> bool:
    """Approver used in automated runs: nobody is there to approve."""
    return False


def approve_all(qualified_name: str, args: dict) -> bool:
    """Approver standing in for a human who says yes to every request."""
    return True


@dataclass
class Gateway:
    task_allowlist: set[str]
    enforce_allowlist: bool = True
    enforce_resources: bool = True
    require_approval_for: set[str] = field(default_factory=lambda: set(APPROVAL_CLASSES))
    block_private_to_public: bool = True
    composite_aware: bool = True
    approver: Callable[[str, dict], bool] = deny_all
    tainted: bool = False  # True once private data entered this session

    def visible(self, qualified_name: str) -> bool:
        """Tools outside the allowlist are not even shown to the model."""
        return not self.enforce_allowlist or qualified_name in self.task_allowlist

    def check(
        self, qualified_name: str, tool: Tool, args: dict, in_task_args: bool = True
    ) -> tuple[bool, str]:
        if self.enforce_allowlist and qualified_name not in self.task_allowlist:
            return False, "tool is not on the allowlist for this task"
        if self.enforce_resources and not in_task_args:
            return False, "tool used on a resource this task does not cover"

        if self.block_private_to_public:
            if self.composite_aware:
                is_flow = tool.data_class == "private_to_public" or (
                    self.tainted and tool.data_class == "public_write"
                )
                if is_flow and not self.approver(qualified_name, args):
                    return False, "private-to-public data flow needs human approval"
            elif self.tainted and tool.data_class in PUBLIC_CLASSES:
                return False, "public write blocked: private data was read in this session"

        if tool.data_class in self.require_approval_for and not self.approver(qualified_name, args):
            return False, "human approval required and not given"
        return True, ""

    def observe(self, tool: Tool) -> None:
        """Called after a successful tool call."""
        if tool.data_class == "private_read":
            self.tainted = True
