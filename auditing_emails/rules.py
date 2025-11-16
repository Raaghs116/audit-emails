"""
Rule and configuration helpers for the Auditing Emails project.
"""

from dataclasses import dataclass, field
from typing import Set


DEFAULT_ROLE_PREFIXES = {
    "info", "support", "sales", "contact", "admin", "billing",
    "help", "office", "newsletter", "hello", "service",
}


@dataclass
class AuditConfig:
    require_mx: bool = True
    drop_disposable: bool = True
    drop_freemail: bool = False
    drop_role_accounts: bool = False
    dedupe: bool = True

    freemail_domains: Set[str] = field(default_factory=set)
    disposable_domains: Set[str] = field(default_factory=set)
    blocklist_domains: Set[str] = field(default_factory=set)
    role_prefixes: Set[str] = field(default_factory=lambda: set(DEFAULT_ROLE_PREFIXES))


def is_role_account(local_part: str, role_prefixes: Set[str]) -> bool:
    """Heuristic detection of role accounts like info@, support@, etc."""
    local = (local_part or "").split("+", 1)[0].lower()
    for prefix in role_prefixes:
        if local == prefix or local.startswith(prefix + ".") or local.startswith(prefix + "-"):
            return True
    return False
