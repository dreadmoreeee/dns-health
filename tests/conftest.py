import sys
from pathlib import Path

import pytest

ROOT = str(Path(__file__).resolve().parent.parent)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from dns_health.model import RR, Answer  # noqa: E402
from dns_health.testing import FakeResolver  # noqa: E402

D = "example.com"
SOA = "ns1.dnsa.net. hostmaster.example.com. 2026010101 7200 3600 1209600 3600"


def base_records():
    return {
        (D, "NS"): [(86400, "ns1.dnsa.net."), (86400, "ns2.dnsb.org.")],
        ("ns1.dnsa.net", "A"): [(300, "192.0.2.1")],
        ("ns2.dnsb.org", "A"): [(300, "198.51.100.1")],
        ("ns2.dnsb.org", "AAAA"): [(300, "2001:db8::1")],
        (D, "SOA"): [(3600, SOA)],
        (D, "A"): [(3600, "203.0.113.10")],
        (D, "AAAA"): [(3600, "2001:db8::10")],
        ("www." + D, "A"): [(3600, "203.0.113.10")],
        ("www." + D, "AAAA"): [(3600, "2001:db8::10")],
        (D, "CAA"): [(3600, '0 issue "letsencrypt.org"')],
        (D, "MX"): [(3600, "10 mail.example.com.")],
        (D, "TXT"): [(3600, '"v=spf1 include:_spf.example.net -all"')],
        ("_dmarc." + D, "TXT"): [(3600, '"v=DMARC1; p=none"')],
    }


def _signed(expiry="20991231000000"):
    """Overrides that make the zone look DNSSEC-signed."""
    rrsig = f"DNSKEY 13 2 3600 {expiry} 20250101000000 12345 example.com. abcd"
    return {
        (D, "DS"): Answer("NOERROR", [RR(D, "DS", 3600, "12345 13 2 ABCD")]),
        (D, "DNSKEY"): Answer("NOERROR", [RR(D, "DNSKEY", 3600, "257 3 13 AAAA"), RR(D, "RRSIG", 3600, rrsig)]),
    }


@pytest.fixture
def make_zone():
    def make(extra=None, remove=(), overrides=None):
        rec = base_records()
        for key in remove:
            rec.pop(key, None)
        rec.update(extra or {})
        return FakeResolver(rec, overrides)
    return make


@pytest.fixture
def signed():
    return _signed
