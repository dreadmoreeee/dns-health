"""Render a Report as Markdown or JSON."""

from __future__ import annotations

import json

from .checks import CHECK_ORDER
from .model import Report

TITLES = {
    "ns": "Nameservers",
    "soa": "SOA",
    "delegation": "Delegation (direct queries)",
    "dnssec": "DNSSEC",
    "caa": "CAA and certificate",
    "addresses": "Addresses",
    "ttl": "TTL",
    "www": "www vs apex",
    "wildcard": "Wildcard",
    "subdomains": "Subdomains (dangling CNAME)",
    "mail": "Mail pointers (MX, SPF, DMARC)",
}
MARKS = {"ok": "OK", "info": "INFO", "warning": "WARN", "error": "ERROR"}


def to_json(report: Report) -> str:
    data = {
        "domain": report.domain,
        "worst": report.worst(),
        "summary": report.counts(),
        "findings": [f.to_dict() for f in report.findings],
    }
    return json.dumps(data, indent=2, ensure_ascii=True)


def to_markdown(report: Report) -> str:
    lines = [f"# DNS health: {report.domain}", ""]
    for check in CHECK_ORDER:
        items = [f for f in report.findings if f.check == check]
        if not items:
            continue
        lines += [f"## {TITLES[check]}", ""]
        for f in items:
            tail = f": {f.detail}" if f.detail else ""
            lines.append(f"- **{MARKS[f.severity]}** {f.title}{tail}")
        lines.append("")
    c = report.counts()
    lines.append(f"**Summary:** {c['error']} error(s), {c['warning']} warning(s), {c['info']} info, {c['ok']} ok")
    return "\n".join(lines) + "\n"
