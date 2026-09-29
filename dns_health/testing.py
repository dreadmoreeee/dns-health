"""In-memory resolver for tests and for trying checks without a network."""

from __future__ import annotations

from .model import RR, Answer


class FakeResolver:
    """Records are given as {(name, rtype): [(ttl, data), ...]}.

    A name that has no records of any type is NXDOMAIN; a known name with a
    missing type is NODATA. `overrides` maps a key to a ready-made Answer:
    (name, rtype) for recursive queries, (ip, name, rtype) for direct ones.
    Direct queries answer from the same zone with aa=True, unless overridden.
    """

    def __init__(self, records=None, overrides=None):
        self.records = {(n.lower(), t): v for (n, t), v in (records or {}).items()}
        self.overrides = overrides or {}
        self.calls: list[tuple] = []

    def _lookup(self, name: str, rtype: str, aa: bool) -> Answer:
        name = name.lower().rstrip(".")
        rows = self.records.get((name, rtype))
        if rows:
            return Answer("NOERROR", [RR(name, rtype, ttl, data) for ttl, data in rows], aa)
        if any(n == name for n, _ in self.records):
            return Answer("NODATA", [], aa)
        return Answer("NXDOMAIN", [], aa)

    def query(self, name, rdtype, dnssec=False):
        self.calls.append(("query", name, rdtype))
        key = (name.lower().rstrip("."), rdtype)
        if key in self.overrides:
            return self.overrides[key]
        return self._lookup(name, rdtype, False)

    def query_server(self, server_ip, name, rdtype):
        self.calls.append(("server", server_ip, name, rdtype))
        key = (server_ip, name.lower().rstrip("."), rdtype)
        if key in self.overrides:
            return self.overrides[key]
        return self._lookup(name, rdtype, True)
