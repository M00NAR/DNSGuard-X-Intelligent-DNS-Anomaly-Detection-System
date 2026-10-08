"""Whitelist of known-safe domains.

Supports plain ``domain`` lines and Tranco-style ``rank,domain`` CSV lines.
A name is whitelisted when its registered (parent) domain is in the list, so that
``mail.google.com`` is covered by a ``google.com`` entry.
"""

from __future__ import annotations

from pathlib import Path


class Whitelist:
    """Case-insensitive set of safe parent domains."""

    def __init__(self, domains: set[str] | None = None) -> None:
        self._domains: set[str] = {d.lower().strip(".") for d in (domains or set())}

    def __len__(self) -> int:
        return len(self._domains)

    def __contains__(self, parent_domain: str) -> bool:
        return parent_domain.lower().strip(".") in self._domains

    def is_whitelisted(self, parent_domain: str | None) -> bool:
        """Return True if ``parent_domain`` (a registered domain) is on the list."""
        if not parent_domain:
            return False
        return parent_domain.lower().strip(".") in self._domains

    @classmethod
    def load(cls, path: str | Path | None, enabled: bool = True) -> "Whitelist":
        """Load a whitelist file. Returns an empty (disabled) whitelist if ``enabled`` is False."""
        if not enabled or not path:
            return cls(set())
        p = Path(path)
        if not p.is_file():
            return cls(set())
        domains: set[str] = set()
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Accept "rank,domain" or bare "domain".
                token = line.split(",")[-1] if "," in line else line
                token = token.strip().strip('"').lower().rstrip(".")
                if token:
                    domains.add(token)
        return cls(domains)
