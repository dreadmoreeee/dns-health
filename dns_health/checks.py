"""The checks. Each takes a Context and returns a list of Findings."""

from __future__ import annotations

import ipaddress
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from .model import Answer, Finding, Report
from .takeover import match_service
from .tls import caa_domains_for_issuer

# RFC 1912 section 2.2 recommended SOA timers (seconds). `minimum` is the
# negative-cache TTL (RFC 2308); RFC 1912 predates it, so the range is wide.
SOA_RANGES = {
    "refresh": (1200, 43200),
    "retry": (180, 7200),
    "expire": (1209600, 2419200),
    "minimum": (300, 259200),
}
RRSIG_SOON = timedelta(days=7)

CHECK_ORDER = (
    "ns", "soa", "delegation", "dnssec", "caa", "addresses", "ttl",
    "www", "wildcard", "subdomains", "mail",
)


class ResolutionError(Exception):
    """The domain could not be looked up at all (exit code 2)."""


@dataclass
class Context:
    domain: str
    resolver: object
    tls_issuer: Callable[[str], str] | None = None
    has_ipv6: Callable[[], bool] | None = None   # does this machine have an IPv6 route?
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    subdomains: tuple[str, ...] = ()
    random_label: Callable[[], str] = lambda: "dnshealth-" + secrets.token_hex(6)
    ns_hosts: list[str] = field(default_factory=list)
    ns_ips: dict[str, list[str]] = field(default_factory=dict)
    _cache: dict = field(default_factory=dict)

    def q(self, name: str, rtype: str, dnssec: bool = False) -> Answer:
        key = (name, rtype, dnssec)
        if key not in self._cache:
            self._cache[key] = self.resolver.query(name, rtype, dnssec)
        return self._cache[key]

    def auth(self, name: str, rtype: str) -> Answer | None:
        """First usable direct answer from the zone's own nameservers, else None."""
        for host in self.ns_hosts:
            for ip in self.ns_ips.get(host, []):
                ans = self.resolver.query_server(ip, name, rtype)
                if ans.status in ("NOERROR", "NODATA") and ans.aa:
                    return ans
        return None


def _f(check: str, severity: str, title: str, detail: str = "") -> Finding:
    return Finding(check, severity, title, detail)


def _host(rdata: str) -> str:
    return rdata.strip().rstrip(".").lower()


def _network(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _provider(host: str) -> str:
    labels = host.split(".")
    return ".".join(labels[-2:])


# ---------------------------------------------------------------- ns

def check_ns(ctx: Context) -> list[Finding]:
    out = []
    hosts = ctx.ns_hosts
    if not hosts:
        return [_f("ns", "error", "No NS records", f"{ctx.domain} has no NS records; is it a registered domain apex?")]
    listing = ", ".join(hosts)
    if len(hosts) < 2:
        out.append(_f("ns", "error", "Only one nameserver", f"RFC 2182 asks for at least two: {listing}"))
    else:
        out.append(_f("ns", "ok", f"{len(hosts)} nameservers", listing))

    missing = [h for h in hosts if not ctx.ns_ips.get(h)]
    for h in missing:
        out.append(_f("ns", "error", "Nameserver does not resolve", f"{h} has no A or AAAA record"))
    ips = [ip for h in hosts for ip in ctx.ns_ips.get(h, [])]
    if len(hosts) >= 2 and ips:
        nets = {_network(ip) for ip in ips}
        if len(nets) < 2:
            out.append(_f("ns", "warning", "Nameservers share one network",
                          f"All addresses are in {next(iter(nets))}; one outage or routing problem takes all of them down"))
        else:
            out.append(_f("ns", "ok", "Nameservers are on different networks", ", ".join(sorted(nets))))
        providers = {_provider(h) for h in hosts}
        if len(providers) < 2:
            out.append(_f("ns", "info", "Single DNS provider",
                          f"All nameservers are under {next(iter(providers))}; fine for most sites, "
                          "but a second provider survives a provider-wide outage"))
        else:
            out.append(_f("ns", "ok", "Several DNS providers", ", ".join(sorted(providers))))
    return out


# ---------------------------------------------------------------- soa

def _soa_fields(data: str):
    parts = data.split()
    if len(parts) < 7:
        return None
    try:
        return parts[0].rstrip("."), parts[1].rstrip("."), *(int(x) for x in parts[2:7])
    except ValueError:
        return None


def _serial_is_dated(serial: int) -> bool:
    s = str(serial)
    if len(s) != 10:
        return False
    try:
        datetime.strptime(s[:8], "%Y%m%d")
    except ValueError:
        return False
    return 1970 <= int(s[:4]) <= 2100


def check_soa(ctx: Context) -> list[Finding]:
    ans = ctx.q(ctx.domain, "SOA")
    rrs = ans.of("SOA")
    if not rrs:
        return [_f("soa", "error", "No SOA record", f"{ctx.domain} returned {ans.status}")]
    parsed = _soa_fields(rrs[0].data)
    if not parsed:
        return [_f("soa", "error", "Unreadable SOA record", rrs[0].data)]
    _, _, serial, refresh, retry, expire, minimum = parsed
    out = []
    if _serial_is_dated(serial):
        out.append(_f("soa", "ok", "Serial is date based", f"{serial} (YYYYMMDDnn)"))
    else:
        out.append(_f("soa", "info", "Serial is not YYYYMMDDnn",
                      f"{serial}; a plain counter or timestamp is valid, the date format is only a convention"))
    values = {"refresh": refresh, "retry": retry, "expire": expire, "minimum": minimum}
    for name, value in values.items():
        lo, hi = SOA_RANGES[name]
        if lo <= value <= hi:
            out.append(_f("soa", "ok", f"SOA {name} in range", f"{value} (recommended {lo}-{hi})"))
        else:
            out.append(_f("soa", "warning", f"SOA {name} outside recommended range",
                          f"{value}; RFC 1912 recommends {lo}-{hi}"))
    if retry >= refresh:
        out.append(_f("soa", "warning", "SOA retry is not shorter than refresh", f"retry {retry} >= refresh {refresh}"))
    return out


# ---------------------------------------------------------------- delegation

def check_delegation(ctx: Context) -> list[Finding]:
    if not ctx.ns_hosts:
        return []
    out = []
    serials: dict[str, int] = {}
    silent_v6: list[str] = []
    asked = 0
    for host in ctx.ns_hosts:
        for ip in ctx.ns_ips.get(host, []):
            asked += 1
            label = f"{host} ({ip})"
            ans = ctx.resolver.query_server(ip, ctx.domain, "SOA")
            v6 = ":" in ip
            if ans.status == "TIMEOUT" or ans.status == "ERROR":
                if v6:
                    silent_v6.append(label)
                else:
                    out.append(_f("delegation", "error", "Nameserver does not answer", label))
                continue
            if ans.status == "SERVFAIL" or ans.status == "NXDOMAIN" or not ans.of("SOA"):
                out.append(_f("delegation", "error", "Lame delegation",
                              f"{label} is listed as NS but has no SOA for the zone ({ans.status})"))
                continue
            if not ans.aa:
                out.append(_f("delegation", "error", "Lame delegation",
                              f"{label} answered without the AA flag; it is not authoritative for the zone"))
                continue
            parsed = _soa_fields(ans.of("SOA")[0].data)
            if parsed:
                serials[label] = parsed[2]
            out.append(_f("delegation", "ok", "Authoritative answer", label))
    v6_total = sum(1 for ips in ctx.ns_ips.values() for ip in ips if ":" in ip)
    if silent_v6 and len(silent_v6) == v6_total and ctx.has_ipv6 is not None and not ctx.has_ipv6():
        out.append(_f("delegation", "info", "IPv6 not tested",
                      f"this machine has no IPv6 route, so the {len(silent_v6)} IPv6 nameserver "
                      "address(es) could not be queried; run it from an IPv6 network to check them"))
    elif silent_v6:
        out.append(_f("delegation", "warning", "No answer over IPv6",
                      f"{len(silent_v6)} IPv6 address(es) did not answer ({', '.join(silent_v6)}); "
                      "this host may simply have no IPv6 route"))
    if asked == 0:
        return [_f("delegation", "error", "No nameserver addresses to test", "none of the NS hosts resolved")]
    if len(set(serials.values())) > 1:
        detail = "; ".join(f"{k}: {v}" for k, v in sorted(serials.items()))
        out.append(_f("delegation", "warning", "SOA serials differ between nameservers",
                      detail + " (may be a zone transfer in progress, or secondaries that are stuck)"))
    elif serials:
        out.append(_f("delegation", "ok", "SOA serials agree", str(next(iter(serials.values())))))
    return out


# ---------------------------------------------------------------- dnssec

def _rrsig_expiry(data: str) -> datetime | None:
    parts = data.split()
    if len(parts) < 6:
        return None
    raw = parts[4]
    try:
        if len(raw) == 14:
            return datetime.strptime(raw, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        return datetime.fromtimestamp(int(raw), timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def check_dnssec(ctx: Context) -> list[Finding]:
    ds = ctx.q(ctx.domain, "DS").of("DS")
    key_ans = ctx.q(ctx.domain, "DNSKEY", True)
    keys = key_ans.of("DNSKEY")
    sigs = [r for r in key_ans.of("RRSIG") if r.data.split()[0] == "DNSKEY"]
    if not ds and not keys:
        return [_f("dnssec", "info", "Zone is not signed", "no DS at the parent and no DNSKEY; DNSSEC is optional")]
    out = []
    if ds and not keys:
        return [_f("dnssec", "error", "DS at parent but no DNSKEY",
                   "validating resolvers will fail every lookup for this domain (SERVFAIL); fix or remove the DS")]
    if keys and not ds:
        out.append(_f("dnssec", "warning", "DNSKEY present but no DS at the parent",
                      "the zone is signed but the chain of trust is not published, so nothing is validated"))
    else:
        out.append(_f("dnssec", "ok", "DS at parent and DNSKEY present", f"{len(ds)} DS, {len(keys)} DNSKEY"))
    if not sigs:
        out.append(_f("dnssec", "error" if ds else "warning", "No RRSIG over the DNSKEY set",
                      "signatures are missing or the resolver did not return them"))
        return out
    expiries = [e for e in (_rrsig_expiry(s.data) for s in sigs) if e]
    if not expiries:
        out.append(_f("dnssec", "warning", "RRSIG expiry unreadable", sigs[0].data))
        return out
    latest = max(expiries)
    if latest <= ctx.now:
        out.append(_f("dnssec", "error", "RRSIG expired", f"expired {latest:%Y-%m-%d %H:%M} UTC"))
    elif latest - ctx.now < RRSIG_SOON:
        out.append(_f("dnssec", "warning", "RRSIG expires soon", f"{latest:%Y-%m-%d %H:%M} UTC"))
    else:
        out.append(_f("dnssec", "ok", "RRSIG valid", f"expires {latest:%Y-%m-%d} UTC"))
    return out


# ---------------------------------------------------------------- caa

def _caa_parse(data: str):
    m = re.match(r'^\s*(\d+)\s+(\w+)\s+"?([^"]*)"?\s*$', data)
    if not m:
        return None
    return m.group(2).lower(), m.group(3).split(";")[0].strip().lower()


def check_caa(ctx: Context) -> list[Finding]:
    ans = ctx.q(ctx.domain, "CAA")
    records = [p for p in (_caa_parse(r.data) for r in ans.of("CAA")) if p]
    if not records:
        hint = '`0 issue "letsencrypt.org"`'
        if ctx.tls_issuer is not None:
            try:
                allowed = caa_domains_for_issuer(ctx.tls_issuer(ctx.domain))
            except OSError:
                allowed = None
            if allowed:
                hint = ", ".join(f'`0 issue "{a}"`' for a in allowed) + " (your current certificate's CA)"
        detail = f"adding {hint} limits which CAs may issue certificates for the domain"
        if any(h.endswith(".ns.cloudflare.com") for h in ctx.ns_hosts):
            detail += ("; on Cloudflare, adding any CAA record also makes Cloudflare add the records "
                       "for the CAs its Universal SSL uses")
        return [_f("caa", "info", "No CAA records", detail)]
    issuers = {v for tag, v in records if tag == "issue"}
    out = [_f("caa", "ok", "CAA present", ", ".join(f"{t} {v!r}" for t, v in records))]
    if not issuers:
        out.append(_f("caa", "info", "CAA has no issue tag", "any CA may issue (only issuewild/iodef are set)"))
        return out
    if ctx.tls_issuer is None:
        return out
    try:
        issuer = ctx.tls_issuer(ctx.domain)
    except OSError as e:
        out.append(_f("caa", "info", "Could not read the TLS certificate", f"{ctx.domain}:443: {e}"))
        return out
    allowed = caa_domains_for_issuer(issuer)
    if allowed is None:
        out.append(_f("caa", "info", "Certificate issuer not in the bundled table",
                      f"issuer {issuer!r}; compare it with the CAA values by hand"))
    elif any(a in issuers for a in allowed):
        out.append(_f("caa", "ok", "Certificate issuer is allowed by CAA", f"{issuer} -> {', '.join(allowed)}"))
    else:
        out.append(_f("caa", "error", "Certificate issuer is not allowed by CAA",
                      f"{issuer} would need one of {', '.join(allowed)}; CAA allows {', '.join(sorted(issuers)) or 'nobody'}. "
                      "The next renewal will be refused"))
    return out


# ---------------------------------------------------------------- addresses / ttl

def _addresses(ctx: Context, name: str):
    a = ctx.q(name, "A").of("A")
    aaaa = ctx.q(name, "AAAA").of("AAAA")
    return a, aaaa


def check_addresses(ctx: Context) -> list[Finding]:
    a, aaaa = _addresses(ctx, ctx.domain)
    if not a and not aaaa:
        return [_f("addresses", "warning", "No A or AAAA at the apex",
                   f"{ctx.domain} does not resolve to an address (fine for a mail-only domain)")]
    out = []
    if a:
        out.append(_f("addresses", "ok", "IPv4 present", ", ".join(sorted(r.data for r in a))))
    else:
        out.append(_f("addresses", "warning", "No IPv4 address", "IPv6-only sites are unreachable for many visitors"))
    if aaaa:
        out.append(_f("addresses", "ok", "IPv6 present", ", ".join(sorted(r.data for r in aaaa))))
    else:
        out.append(_f("addresses", "info", "No IPv6 (AAAA) record", "optional, but IPv6-only networks cannot reach the site"))
    return out


def _ttl_findings(label: str, ttl: int, low_warn: int, low_info: int, high: int) -> list[Finding]:
    if ttl < low_warn:
        return [_f("ttl", "warning", f"{label} TTL very low", f"{ttl}s; increases query load and hurts resilience")]
    if ttl < low_info:
        return [_f("ttl", "info", f"{label} TTL low", f"{ttl}s; fine while migrating, short for steady state")]
    if ttl > high:
        return [_f("ttl", "info", f"{label} TTL high", f"{ttl}s; changes take that long to reach every resolver")]
    return [_f("ttl", "ok", f"{label} TTL", f"{ttl}s")]


def check_ttl(ctx: Context) -> list[Finding]:
    """TTLs are read from an authoritative server, since resolvers report the remaining TTL."""
    out = []
    via_auth = False
    for rtype, low_warn, low_info, high in (("A", 60, 300, 86400), ("AAAA", 60, 300, 86400),
                                            ("MX", 60, 300, 86400), ("NS", 300, 3600, 172800)):
        ans = ctx.auth(ctx.domain, rtype)
        if ans is not None:
            via_auth = True
        else:
            ans = ctx.q(ctx.domain, rtype)
        rrs = ans.of(rtype)
        if rrs:
            out.extend(_ttl_findings(rtype, min(r.ttl for r in rrs), low_warn, low_info, high))
    if out and not via_auth:
        out.append(_f("ttl", "info", "TTLs read through the resolver",
                      "no nameserver answered directly, so values may be the remaining cache time"))
    return out


# ---------------------------------------------------------------- www

def check_www(ctx: Context) -> list[Finding]:
    www = "www." + ctx.domain
    a_apex, aaaa_apex = _addresses(ctx, ctx.domain)
    a_www, aaaa_www = _addresses(ctx, www)
    if not a_www and not aaaa_www:
        return [_f("www", "warning", "www does not resolve", f"{www}: visitors who type www get an error")]
    apex = {r.data for r in a_apex + aaaa_apex}
    sub = {r.data for r in a_www + aaaa_www}
    if apex and apex == sub:
        return [_f("www", "ok", "www and apex resolve to the same addresses", ", ".join(sorted(sub)))]
    if not apex:
        return [_f("www", "info", "Apex has no address, www does", "make sure the apex redirects or is intentionally unused")]
    return [_f("www", "info", "www and apex resolve to different addresses",
               f"apex {', '.join(sorted(apex))}; www {', '.join(sorted(sub))}. "
               "Fine if one redirects to the other (not checked here: DNS only)")]


# ---------------------------------------------------------------- wildcard

def check_wildcard(ctx: Context) -> list[Finding]:
    name = f"{ctx.random_label()}.{ctx.domain}"
    a, aaaa = _addresses(ctx, name)
    if a or aaaa:
        return [_f("wildcard", "info", "Wildcard DNS record",
                   f"{name} resolves to {', '.join(sorted(r.data for r in a + aaaa))}; "
                   "every unknown subdomain answers, so typos and dangling names do not show up as NXDOMAIN")]
    return [_f("wildcard", "ok", "No wildcard", "a random label does not resolve")]


# ---------------------------------------------------------------- subdomains

def _fqdn(sub: str, domain: str) -> str:
    sub = sub.strip().lower().rstrip(".")
    if sub == domain or sub.endswith("." + domain):
        return sub
    return f"{sub}.{domain}"


def check_subdomains(ctx: Context) -> list[Finding]:
    out = []
    for sub in ctx.subdomains:
        name = _fqdn(sub, ctx.domain)
        current, chain = name, []
        verdict = None
        for _ in range(10):
            ans = ctx.q(current, "CNAME")
            if ans.status == "NXDOMAIN":
                if not chain:
                    verdict = _f("subdomains", "info", f"{name} does not exist", "NXDOMAIN; nothing to take over")
                else:
                    service = match_service(current)
                    extra = f" ({service})" if service else ""
                    verdict = _f("subdomains", "error", f"{name}: dangling CNAME",
                                 f"{' -> '.join([name] + chain)} ends in NXDOMAIN{extra}; "
                                 "anyone who can claim that name can serve content on your subdomain")
                break
            if ans.status in ("TIMEOUT", "SERVFAIL", "ERROR"):
                verdict = _f("subdomains", "warning", f"{name}: lookup failed", f"{current}: {ans.status}")
                break
            cnames = ans.of("CNAME")
            if not cnames:
                break
            current = _host(cnames[0].data)
            chain.append(current)
        else:
            verdict = _f("subdomains", "warning", f"{name}: CNAME chain too long", " -> ".join([name] + chain))
        if verdict is None:
            if not chain:
                verdict = _f("subdomains", "ok", f"{name}: no CNAME", "not an alias, nothing dangling")
            else:
                service = next((s for s in map(match_service, chain) if s), None)
                path = " -> ".join([name] + chain)
                if service:
                    verdict = _f("subdomains", "warning", f"{name}: review ({service})",
                                 f"{path}. The target exists now; confirm the {service} resource is still yours, "
                                 "because if it is deleted this name can be claimed")
                else:
                    verdict = _f("subdomains", "ok", f"{name}: CNAME resolves", path)
        out.append(verdict)
    return out


# ---------------------------------------------------------------- mail

def check_mail(ctx: Context) -> list[Finding]:
    out = []
    mx = ctx.q(ctx.domain, "MX").of("MX")
    txt = [r.data.replace('" "', "").strip('"') for r in ctx.q(ctx.domain, "TXT").of("TXT")]
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    dmarc = [r.data.replace('" "', "").strip('"') for r in ctx.q("_dmarc." + ctx.domain, "TXT").of("TXT")]
    dmarc = [t for t in dmarc if t.lower().startswith("v=dmarc1")]

    null_mx = bool(mx) and all(r.data.split()[-1] == "." for r in mx)
    receives = bool(mx) and not null_mx
    if null_mx:
        out.append(_f("mail", "info", "Null MX", "the domain declares that it does not receive mail (RFC 7505)"))
    elif mx:
        hosts = ", ".join(_host(r.data.split()[-1]) for r in sorted(mx, key=lambda r: int(r.data.split()[0])))
        out.append(_f("mail", "ok", "MX records", hosts))
    else:
        out.append(_f("mail", "info", "No MX records", "mail falls back to the A record; add a null MX if the domain sends and receives none"))

    if len(spf) > 1:
        out.append(_f("mail", "error", "Multiple SPF records", f"{len(spf)} v=spf1 records; receivers return permerror. Merge them"))
    elif spf:
        lookups = len(re.findall(r"(?:^|\s)[+\-~?]?(?:include:|a\b|mx\b|ptr\b|exists:|redirect=)", spf[0].lower()))
        if lookups > 10:
            out.append(_f("mail", "warning", "SPF may exceed 10 DNS lookups",
                          f"about {lookups} lookup mechanisms in the top-level record alone (include chains not followed)"))
        else:
            out.append(_f("mail", "ok", "SPF present", f"{spf[0]} (about {lookups} lookup mechanisms; nested includes not followed)"))
    else:
        out.append(_f("mail", "warning" if receives else "info",
                      "No SPF record", "publish v=spf1 (or `v=spf1 -all` if the domain sends no mail)"))

    if dmarc:
        out.append(_f("mail", "ok", "DMARC present", dmarc[0]))
    else:
        out.append(_f("mail", "warning" if receives else "info", "No DMARC record", f"publish a TXT record at _dmarc.{ctx.domain}"))
    return out


CHECKS = {
    "ns": check_ns, "soa": check_soa, "delegation": check_delegation, "dnssec": check_dnssec,
    "caa": check_caa, "addresses": check_addresses, "ttl": check_ttl, "www": check_www,
    "wildcard": check_wildcard, "subdomains": check_subdomains, "mail": check_mail,
}


def normalize_domain(domain: str) -> str:
    d = domain.strip().lower().rstrip(".")
    try:
        d.encode("ascii")
    except UnicodeEncodeError:
        d = d.encode("idna").decode("ascii")
    if not d or " " in d or "/" in d or ".." in d:
        raise ResolutionError(f"not a valid domain name: {domain!r}")
    return d


def run_checks(domain, resolver, *, tls_issuer=None, subdomains=(), now=None, random_label=None,
               has_ipv6=None) -> Report:
    domain = normalize_domain(domain)
    ctx = Context(domain=domain, resolver=resolver, tls_issuer=tls_issuer, subdomains=tuple(subdomains),
                  has_ipv6=has_ipv6)
    if now is not None:
        ctx.now = now
    if random_label is not None:
        ctx.random_label = random_label

    ns = ctx.q(domain, "NS")
    if ns.status == "NXDOMAIN":
        raise ResolutionError(f"{domain} does not exist (NXDOMAIN)")
    if ns.status in ("TIMEOUT", "SERVFAIL", "ERROR"):
        raise ResolutionError(f"could not resolve {domain}: {ns.status} from the resolver")
    ctx.ns_hosts = sorted({_host(r.data) for r in ns.of("NS")})
    for host in ctx.ns_hosts:
        ips = [r.data for r in ctx.q(host, "A").of("A")] + [r.data for r in ctx.q(host, "AAAA").of("AAAA")]
        ctx.ns_ips[host] = ips

    findings: list[Finding] = []
    for name in CHECK_ORDER:
        findings.extend(CHECKS[name](ctx))
    return Report(domain, findings)
