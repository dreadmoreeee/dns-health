"""Resolver interface and the dnspython implementation.

Checks only talk to the small `Resolver` protocol, so tests can swap in
`dns_health.testing.FakeResolver` and never touch the network.
"""

from __future__ import annotations

from typing import Protocol

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from .model import RR, Answer


class Resolver(Protocol):
    def query(self, name: str, rdtype: str, dnssec: bool = False) -> Answer:
        """Ask the configured recursive resolver."""

    def query_server(self, server_ip: str, name: str, rdtype: str) -> Answer:
        """Ask one nameserver directly (no recursion); `aa` is set from the flags."""


def _flatten(rrsets) -> list[RR]:
    out: list[RR] = []
    for rrset in rrsets:
        rtype = dns.rdatatype.to_text(rrset.rdtype)
        for rdata in rrset:
            out.append(RR(str(rrset.name).rstrip(".").lower(), rtype, int(rrset.ttl), rdata.to_text()))
    return out


class DnsResolver:
    def __init__(self, nameserver: str | None = None, timeout: float = 5.0):
        self.timeout = timeout
        self._res = dns.resolver.Resolver(configure=nameserver is None)
        if nameserver:
            self._res.nameservers = [nameserver]
        self._res.lifetime = timeout
        self._res.timeout = timeout

    def query(self, name: str, rdtype: str, dnssec: bool = False) -> Answer:
        if dnssec:
            self._res.use_edns(0, dns.flags.DO, 1232)
        try:
            ans = self._res.resolve(name, rdtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return Answer("NXDOMAIN")
        except dns.resolver.NoAnswer:
            return Answer("NODATA")
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            return Answer("TIMEOUT")
        except dns.resolver.NoNameservers:
            return Answer("SERVFAIL")
        except dns.exception.DNSException:
            return Answer("ERROR")
        rrs = _flatten(ans.response.answer)
        return Answer("NOERROR" if rrs else "NODATA", rrs, bool(ans.response.flags & dns.flags.AA))

    def query_server(self, server_ip: str, name: str, rdtype: str) -> Answer:
        msg = dns.message.make_query(name, rdtype)
        msg.flags &= ~dns.flags.RD
        try:
            resp = dns.query.udp(msg, server_ip, timeout=self.timeout)
            if resp.flags & dns.flags.TC:
                resp = dns.query.tcp(msg, server_ip, timeout=self.timeout)
        except (dns.exception.Timeout, OSError):
            return Answer("TIMEOUT")
        except dns.exception.DNSException:
            return Answer("ERROR")
        rcode = resp.rcode()
        aa = bool(resp.flags & dns.flags.AA)
        if rcode == dns.rcode.NXDOMAIN:
            return Answer("NXDOMAIN", [], aa)
        if rcode != dns.rcode.NOERROR:
            return Answer("SERVFAIL", [], aa)
        rrs = _flatten(resp.answer)
        return Answer("NOERROR" if rrs else "NODATA", rrs, aa)
