from datetime import datetime, timezone

import pytest

from dns_health.checks import ResolutionError, run_checks
from dns_health.model import RR, Answer
from dns_health.takeover import match_service
from dns_health.tls import caa_domains_for_issuer

D = "example.com"
NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def run(res, check, **kw):
    kw.setdefault("now", NOW)
    kw.setdefault("random_label", lambda: "zzrandom")
    rep = run_checks(D, res, **kw)
    return [f for f in rep.findings if f.check == check]


def sev(findings):
    return {f.severity for f in findings}


def titles(findings, severity):
    return [f.title for f in findings if f.severity == severity]


# ---- ns

def test_ns_ok(make_zone):
    f = run(make_zone(), "ns")
    assert sev(f) == {"ok"}


def test_ns_single(make_zone):
    res = make_zone({(D, "NS"): [(300, "ns1.dnsa.net.")]})
    assert "Only one nameserver" in titles(run(res, "ns"), "error")


def test_ns_same_network_and_provider(make_zone):
    res = make_zone({
        (D, "NS"): [(300, "ns1.dnsa.net."), (300, "ns2.dnsa.net.")],
        ("ns2.dnsa.net", "A"): [(300, "192.0.2.77")],
    })
    f = run(res, "ns")
    assert "Nameservers share one network" in titles(f, "warning")
    assert "Single DNS provider" in titles(f, "info")


def test_ns_ipv6_networks_use_48(make_zone):
    res = make_zone({
        (D, "NS"): [(300, "ns1.a.net."), (300, "ns2.b.org.")],
        ("ns1.a.net", "AAAA"): [(300, "2001:db8:1::1")],
        ("ns2.b.org", "AAAA"): [(300, "2001:db8:1:5::1")],
    }, remove=[("ns1.dnsa.net", "A"), ("ns2.dnsb.org", "A"), ("ns2.dnsb.org", "AAAA")])
    assert "Nameservers share one network" in titles(run(res, "ns"), "warning")


def test_ns_unresolvable_host(make_zone):
    res = make_zone(remove=[("ns2.dnsb.org", "A"), ("ns2.dnsb.org", "AAAA")],
                    extra={("ns2.dnsb.org", "TXT"): [(1, "x")]})
    assert "Nameserver does not resolve" in titles(run(res, "ns"), "error")


def test_no_ns_records_is_finding_not_crash(make_zone):
    res = make_zone(overrides={(D, "NS"): Answer("NODATA")})
    assert "No NS records" in titles(run(res, "ns"), "error")


# ---- soa

def test_soa_ok(make_zone):
    assert sev(run(make_zone(), "soa")) == {"ok"}


def test_soa_serial_not_dated(make_zone):
    soa = "ns1.dnsa.net. h.example.com. 1717200000 7200 3600 1209600 3600"
    f = run(make_zone({(D, "SOA"): [(3600, soa)]}), "soa")
    assert "Serial is not YYYYMMDDnn" in titles(f, "info")


def test_soa_serial_bad_date_is_not_dated(make_zone):
    soa = "ns1.dnsa.net. h.example.com. 2026139901 7200 3600 1209600 3600"
    assert "Serial is not YYYYMMDDnn" in titles(run(make_zone({(D, "SOA"): [(3600, soa)]}), "soa"), "info")


def test_soa_out_of_range(make_zone):
    soa = "ns1.dnsa.net. h.example.com. 2026010101 60 30 3600 5"
    f = run(make_zone({(D, "SOA"): [(3600, soa)]}), "soa")
    warned = titles(f, "warning")
    for name in ("refresh", "retry", "expire", "minimum"):
        assert f"SOA {name} outside recommended range" in warned


def test_soa_retry_ge_refresh(make_zone):
    soa = "ns1.dnsa.net. h.example.com. 2026010101 3600 3600 1209600 3600"
    assert "SOA retry is not shorter than refresh" in titles(run(make_zone({(D, "SOA"): [(1, soa)]}), "soa"), "warning")


def test_soa_missing(make_zone):
    assert titles(run(make_zone(remove=[(D, "SOA")]), "soa"), "error") == ["No SOA record"]


# ---- delegation

def test_delegation_ok(make_zone):
    f = run(make_zone(), "delegation")
    assert sev(f) == {"ok"}
    assert "SOA serials agree" in titles(f, "ok")


def test_delegation_lame_not_authoritative(make_zone):
    res = make_zone(overrides={("192.0.2.1", D, "SOA"): Answer("NOERROR", [RR(D, "SOA", 1, SOA_)], aa=False)})
    assert "Lame delegation" in titles(run(res, "delegation"), "error")


def test_delegation_refused(make_zone):
    res = make_zone(overrides={("192.0.2.1", D, "SOA"): Answer("SERVFAIL", aa=False)})
    assert "Lame delegation" in titles(run(res, "delegation"), "error")


def test_delegation_timeout_v4_error_v6_warning(make_zone):
    res = make_zone(overrides={
        ("192.0.2.1", D, "SOA"): Answer("TIMEOUT"),
        ("2001:db8::1", D, "SOA"): Answer("TIMEOUT"),
    })
    f = run(res, "delegation")
    assert "Nameserver does not answer" in titles(f, "error")
    assert "No answer over IPv6" in titles(f, "warning")


def test_delegation_serial_mismatch(make_zone):
    other = "ns1.dnsa.net. h.example.com. 2026010202 7200 3600 1209600 3600"
    res = make_zone(overrides={("198.51.100.1", D, "SOA"): Answer("NOERROR", [RR(D, "SOA", 1, other)], aa=True)})
    assert "SOA serials differ between nameservers" in titles(run(res, "delegation"), "warning")


SOA_ = "ns1.dnsa.net. hostmaster.example.com. 2026010101 7200 3600 1209600 3600"


# ---- dnssec

def test_dnssec_unsigned_is_info(make_zone):
    f = run(make_zone(), "dnssec")
    assert titles(f, "info") == ["Zone is not signed"]
    assert not titles(f, "error")


def test_dnssec_ok(make_zone, signed):
    f = run(make_zone(overrides=signed()), "dnssec")
    assert sev(f) == {"ok"}


def test_dnssec_expired(make_zone, signed):
    f = run(make_zone(overrides=signed("20260101000000")), "dnssec")
    assert titles(f, "error") == ["RRSIG expired"]


def test_dnssec_expiring_soon(make_zone, signed):
    f = run(make_zone(overrides=signed("20260605000000")), "dnssec")
    assert titles(f, "warning") == ["RRSIG expires soon"]


def test_dnssec_epoch_expiry(make_zone, signed):
    ep = str(int(datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()))
    assert "RRSIG expired" in titles(run(make_zone(overrides=signed(ep)), "dnssec"), "error")


def test_dnssec_ds_without_dnskey(make_zone, signed):
    ov = signed()
    del ov[(D, "DNSKEY")]
    assert "DS at parent but no DNSKEY" in titles(run(make_zone(overrides=ov), "dnssec"), "error")


def test_dnssec_dnskey_without_ds(make_zone, signed):
    ov = signed()
    del ov[(D, "DS")]
    assert "DNSKEY present but no DS at the parent" in titles(run(make_zone(overrides=ov), "dnssec"), "warning")


def test_dnssec_no_rrsig(make_zone, signed):
    ov = signed()
    ov[(D, "DNSKEY")] = Answer("NOERROR", [RR(D, "DNSKEY", 1, "257 3 13 AAAA")])
    assert "No RRSIG over the DNSKEY set" in titles(run(make_zone(overrides=ov), "dnssec"), "error")


# ---- caa

def issuer(name):
    return lambda host: name


def test_caa_allows_issuer(make_zone):
    f = run(make_zone(), "caa", tls_issuer=issuer("Let's Encrypt (R11)"))
    assert "Certificate issuer is allowed by CAA" in titles(f, "ok")


def test_caa_blocks_issuer(make_zone):
    f = run(make_zone(), "caa", tls_issuer=issuer("DigiCert Inc (DigiCert TLS RSA)"))
    assert "Certificate issuer is not allowed by CAA" in titles(f, "error")


def test_caa_google_and_sectigo(make_zone):
    res = make_zone({(D, "CAA"): [(1, '0 issue "pki.goog"'), (1, '0 issue "sectigo.com; validationmethods=dns-01"')]})
    assert not titles(run(res, "caa", tls_issuer=issuer("Google Trust Services (WE1)")), "error")
    assert not titles(run(res, "caa", tls_issuer=issuer("Sectigo Limited")), "error")


def test_caa_missing_is_info(make_zone):
    f = run(make_zone(remove=[(D, "CAA")]), "caa", tls_issuer=issuer("Let's Encrypt"))
    assert titles(f, "info") == ["No CAA records"]


def test_caa_unknown_issuer(make_zone):
    f = run(make_zone(), "caa", tls_issuer=issuer("Mystery CA"))
    assert "Certificate issuer not in the bundled table" in titles(f, "info")


def test_caa_tls_failure(make_zone):
    def boom(host):
        raise OSError("refused")
    f = run(make_zone(), "caa", tls_issuer=boom)
    assert "Could not read the TLS certificate" in titles(f, "info")


def test_issuer_table():
    assert caa_domains_for_issuer("Let's Encrypt (E5)") == ("letsencrypt.org",)
    assert caa_domains_for_issuer("nobody") is None


# ---- addresses / ttl

def test_addresses_ok(make_zone):
    assert sev(run(make_zone(), "addresses")) == {"ok"}


def test_addresses_no_ipv6(make_zone):
    assert "No IPv6 (AAAA) record" in titles(run(make_zone(remove=[(D, "AAAA")]), "addresses"), "info")


def test_addresses_none(make_zone):
    f = run(make_zone(remove=[(D, "A"), (D, "AAAA")]), "addresses")
    assert titles(f, "warning") == ["No A or AAAA at the apex"]


def test_ttl_ok(make_zone):
    assert sev(run(make_zone(), "ttl")) == {"ok"}


def test_ttl_too_low_and_too_high(make_zone):
    res = make_zone({(D, "A"): [(10, "203.0.113.10")], (D, "AAAA"): [(604800, "2001:db8::10")]})
    f = run(res, "ttl")
    assert "A TTL very low" in titles(f, "warning")
    assert "AAAA TTL high" in titles(f, "info")


def test_ttl_uses_authoritative_not_recursive(make_zone):
    res = make_zone(overrides={(D, "A"): Answer("NOERROR", [RR(D, "A", 5, "203.0.113.10")])})
    assert sev([f for f in run(res, "ttl") if f.title.startswith("A ")]) == {"ok"}


# ---- www / wildcard

def test_www_same(make_zone):
    assert titles(run(make_zone(), "www"), "ok")


def test_www_different(make_zone):
    res = make_zone({("www." + D, "A"): [(1, "203.0.113.99")]})
    assert titles(run(res, "www"), "info") == ["www and apex resolve to different addresses"]


def test_www_missing(make_zone):
    res = make_zone(remove=[("www." + D, "A"), ("www." + D, "AAAA")])
    assert titles(run(res, "www"), "warning") == ["www does not resolve"]


def test_wildcard_absent(make_zone):
    assert titles(run(make_zone(), "wildcard"), "ok") == ["No wildcard"]


def test_wildcard_present(make_zone):
    res = make_zone({("zzrandom." + D, "A"): [(1, "203.0.113.10")]})
    assert titles(run(res, "wildcard"), "info") == ["Wildcard DNS record"]


# ---- subdomains

def test_subdomain_missing_is_info(make_zone):
    f = run(make_zone(), "subdomains", subdomains=["admin"])
    assert titles(f, "info") == ["admin.example.com does not exist"]


def test_subdomain_plain_a_ok(make_zone):
    f = run(make_zone(), "subdomains", subdomains=["www"])
    assert titles(f, "ok") == ["www.example.com: no CNAME"]


def test_subdomain_cname_ok(make_zone):
    res = make_zone({("app." + D, "CNAME"): [(1, "lb.provider.net.")], ("lb.provider.net", "A"): [(1, "192.0.2.9")]})
    assert titles(run(res, "subdomains", subdomains=["app"]), "ok") == ["app.example.com: CNAME resolves"]


def test_subdomain_dangling_nxdomain(make_zone):
    res = make_zone({("old." + D, "CNAME"): [(1, "gone.provider.net.")]})
    f = run(res, "subdomains", subdomains=["old"])
    assert titles(f, "error") == ["old.example.com: dangling CNAME"]


def test_subdomain_dangling_takeover_service_named(make_zone):
    res = make_zone({("demo." + D, "CNAME"): [(1, "shop.herokuapp.com.")]})
    f = run(res, "subdomains", subdomains=["demo"])
    assert titles(f, "error") and "Heroku" in f[0].detail


def test_subdomain_takeover_service_existing_is_review_not_error(make_zone):
    res = make_zone({("demo." + D, "CNAME"): [(1, "me.github.io.")], ("me.github.io", "A"): [(1, "192.0.2.5")]})
    f = run(res, "subdomains", subdomains=["demo"])
    assert titles(f, "warning") == ["demo.example.com: review (GitHub Pages)"]
    assert not titles(f, "error")


def test_subdomain_chain_second_hop_dangling(make_zone):
    res = make_zone({("a." + D, "CNAME"): [(1, "b.other.net.")], ("b.other.net", "CNAME"): [(1, "c.gone.net.")]})
    assert titles(run(res, "subdomains", subdomains=["a"]), "error")


def test_subdomain_lookup_failure(make_zone):
    res = make_zone(overrides={("x." + D, "CNAME"): Answer("TIMEOUT")})
    assert titles(run(res, "subdomains", subdomains=["x"]), "warning") == ["x.example.com: lookup failed"]


def test_subdomain_full_name_accepted(make_zone):
    f = run(make_zone(), "subdomains", subdomains=["www.example.com"])
    assert f[0].title == "www.example.com: no CNAME"


@pytest.mark.parametrize("host,service", [
    ("x.herokuapp.com", "Heroku"),
    ("me.github.io", "GitHub Pages"),
    ("a.azurewebsites.net", "Azure App Service"),
    ("a.cloudapp.net", "Azure Cloud Services"),
    ("b.s3-website-us-east-1.amazonaws.com", "AWS S3 website"),
    ("b.s3-website.ca-central-1.amazonaws.com", "AWS S3 website"),
    ("site.netlify.app", "Netlify"),
    ("example.org", None),
    ("notgithub.io", None),
    ("bucket.s3.amazonaws.com", None),
])
def test_match_service(host, service):
    assert match_service(host) == service


# ---- mail

def test_mail_ok(make_zone):
    assert sev(run(make_zone(), "mail")) == {"ok"}


def test_mail_multiple_spf(make_zone):
    res = make_zone({(D, "TXT"): [(1, '"v=spf1 -all"'), (1, '"v=spf1 +all"')]})
    assert "Multiple SPF records" in titles(run(res, "mail"), "error")


def test_mail_spf_too_many_lookups(make_zone):
    spf = "v=spf1 " + " ".join(f"include:s{i}.example.net" for i in range(11)) + " -all"
    res = make_zone({(D, "TXT"): [(1, f'"{spf}"')]})
    assert "SPF may exceed 10 DNS lookups" in titles(run(res, "mail"), "warning")


def test_mail_no_spf_no_dmarc(make_zone):
    res = make_zone(remove=[(D, "TXT"), ("_dmarc." + D, "TXT")])
    w = titles(run(res, "mail"), "warning")
    assert "No SPF record" in w and "No DMARC record" in w


def test_mail_null_mx_only_info(make_zone):
    res = make_zone({(D, "MX"): [(1, "0 .")]}, remove=[(D, "TXT"), ("_dmarc." + D, "TXT")])
    f = run(res, "mail")
    assert not titles(f, "warning") and "Null MX" in titles(f, "info")


# ---- resolution errors

def test_nxdomain_raises(make_zone):
    with pytest.raises(ResolutionError):
        run_checks("nope.invalid", make_zone())


def test_resolver_timeout_raises(make_zone):
    with pytest.raises(ResolutionError):
        run_checks(D, make_zone(overrides={(D, "NS"): Answer("TIMEOUT")}))


def test_bad_domain_raises(make_zone):
    with pytest.raises(ResolutionError):
        run_checks("bad domain", make_zone())


def test_ipv6_not_tested_when_this_machine_has_no_ipv6_route(make_zone):
    res = make_zone(overrides={("2001:db8::1", D, "SOA"): Answer("TIMEOUT")})
    f = run(res, "delegation", has_ipv6=lambda: False)
    assert "IPv6 not tested" in titles(f, "info")
    assert "No answer over IPv6" not in titles(f, "warning")
    f = run(res, "delegation", has_ipv6=lambda: True)
    assert "No answer over IPv6" in titles(f, "warning")


def test_missing_caa_hint_follows_the_current_certificate(make_zone):
    f = run(make_zone(remove=[(D, "CAA")]), "caa", tls_issuer=issuer("Google Trust Services (WE1)"))
    assert '0 issue "pki.goog"' in f[0].detail and "letsencrypt" not in f[0].detail
    f = run(make_zone(remove=[(D, "CAA")], overrides={}), "caa")
    assert "letsencrypt.org" in f[0].detail
