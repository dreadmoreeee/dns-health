"""Command line: python -m dns_health DOMAIN [--subdomains a,b] [--format json]."""

from __future__ import annotations

import argparse
import sys

from .checks import ResolutionError, run_checks
from .report import to_json, to_markdown
from .resolver import DnsResolver
from .tls import fetch_issuer


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dns-health", description="DNS health report for a domain.")
    p.add_argument("domain")
    p.add_argument("--subdomains", default="", help="comma separated labels to check for dangling CNAMEs")
    p.add_argument("--format", choices=("markdown", "json"), default="markdown")
    p.add_argument("--fail-on", choices=("info", "warning", "error"), default="error",
                   help="exit 1 when a finding of this severity or worse exists (default: error)")
    p.add_argument("--resolver", metavar="IP", help="recursive resolver to use (default: system)")
    p.add_argument("--timeout", type=float, default=5.0, help="seconds per query (default 5)")
    p.add_argument("--no-tls", action="store_true", help="do not connect to port 443 to read the certificate issuer")
    return p


def local_ipv6_route() -> bool:
    """True when the OS has a route to the IPv6 internet (a UDP connect sends nothing)."""
    import socket
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(("2606:4700:4700::1111", 53))
        return True
    except OSError:
        return False


def main(argv=None, resolver=None, tls_issuer=None, out=None) -> int:
    out = out or sys.stdout
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    if resolver is None:
        resolver = DnsResolver(args.resolver, args.timeout)
    if tls_issuer is None and not args.no_tls:
        tls_issuer = lambda host: fetch_issuer(host, timeout=args.timeout)  # noqa: E731
    subs = [s.strip() for s in args.subdomains.split(",") if s.strip()]
    try:
        report = run_checks(args.domain, resolver, tls_issuer=tls_issuer, subdomains=subs,
                            has_ipv6=local_ipv6_route)
    except ResolutionError as e:
        print(f"dns-health: {e}", file=sys.stderr)
        return 2
    out.write(to_json(report) + "\n" if args.format == "json" else to_markdown(report))
    return 1 if report.failing(args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
