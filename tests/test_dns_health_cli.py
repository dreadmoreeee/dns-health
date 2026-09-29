import io
import json

from dns_health.cli import main
from dns_health.model import Finding, Report
from dns_health.report import to_json, to_markdown


def run_cli(argv, res, issuer=lambda h: "Let's Encrypt (R11)"):
    out = io.StringIO()
    code = main(argv, resolver=res, tls_issuer=issuer, out=out)
    return code, out.getvalue()


def test_markdown_default_exit_0(make_zone):
    code, text = run_cli(["example.com"], make_zone())
    assert code == 0
    assert text.startswith("# DNS health: example.com")
    assert "## Nameservers" in text and "## DNSSEC" in text
    assert "**INFO** Zone is not signed" in text
    assert "0 error(s)" in text


def test_json_output(make_zone):
    code, text = run_cli(["example.com", "--format", "json", "--subdomains", "www,admin"], make_zone())
    data = json.loads(text)
    assert code == 0
    assert data["domain"] == "example.com"
    assert data["summary"]["error"] == 0
    assert {f["check"] for f in data["findings"]} >= {"ns", "soa", "dnssec", "subdomains", "mail"}
    assert all(set(f) == {"check", "severity", "title", "detail"} for f in data["findings"])
    assert text.isascii()


def test_exit_1_on_error(make_zone):
    res = make_zone({("old.example.com", "CNAME"): [(1, "gone.provider.net.")]})
    code, text = run_cli(["example.com", "--subdomains", "old"], res)
    assert code == 1
    assert "dangling CNAME" in text


def test_fail_on_warning_and_info(make_zone):
    res = make_zone(remove=[("example.com", "AAAA")])  # info only, no IPv6
    assert run_cli(["example.com"], res)[0] == 0
    assert run_cli(["example.com", "--fail-on", "info"], res)[0] == 1
    res = make_zone(remove=[("_dmarc.example.com", "TXT")])  # warning
    assert run_cli(["example.com"], res)[0] == 0
    assert run_cli(["example.com", "--fail-on", "warning"], res)[0] == 1


def test_exit_2_nxdomain(make_zone, capsys):
    code, _ = run_cli(["nope.invalid"], make_zone())
    assert code == 2
    assert "does not exist" in capsys.readouterr().err


def test_exit_2_usage():
    assert main(["--format", "xml", "example.com"]) == 2
    assert main([]) == 2


def test_no_tls_skips_issuer(make_zone):
    calls = []
    out = io.StringIO()
    main(["example.com", "--no-tls"], resolver=make_zone(), tls_issuer=None, out=out)
    assert "issuer" not in out.getvalue().lower()
    assert calls == []


def test_report_helpers():
    rep = Report("x.test", [Finding("ns", "ok", "a"), Finding("ns", "warning", "b", "why")])
    assert rep.worst() == "warning"
    assert rep.counts() == {"ok": 1, "info": 0, "warning": 1, "error": 0}
    assert rep.failing("warning") and not rep.failing("error")
    assert "- **WARN** b: why" in to_markdown(rep)
    assert json.loads(to_json(rep))["worst"] == "warning"
