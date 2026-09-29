# dns-health

A DNS health report for a domain: one command, Markdown or JSON, with an exit code you can use in CI. It needs only [dnspython](https://www.dnspython.org/).

```
python -m dns_health example.com --subdomains www,demo,admin
python -m dns_health example.com --format json --fail-on warning --resolver 1.1.1.1
```

What it checks:

- **Nameservers**: at least two, on different /24 (IPv4) or /48 (IPv6) networks, and under different providers (guessed from the last two labels of the NS host name).
- **SOA**: serial in `YYYYMMDDnn` form (otherwise info, since counters are valid) and refresh/retry/expire/minimum against the RFC 1912 ranges.
- **Delegation**: every NS address is asked directly for the SOA. No answer, no SOA or no AA flag is a lame delegation; different serials are a warning.
- **DNSSEC**: DS at the parent, DNSKEY, and RRSIG expiry (warns under 7 days). An unsigned zone is reported as info, not a failure.
- **CAA**: records present, and whether the issuer of the certificate served on port 443 is allowed (Let's Encrypt, Google Trust Services, DigiCert, Sectigo, GlobalSign, Amazon, GoDaddy and a few more are mapped). No CAA is an info with a suggestion.
- **Addresses, TTL, www vs apex, wildcard**: A/AAAA present, TTLs read from an authoritative server (resolvers only show the remaining cache time), www resolving to the same addresses as the apex, and a random label to detect wildcards.
- **Dangling CNAMEs** for `--subdomains`: the CNAME chain is followed; a target that is NXDOMAIN is an **error**. A target on a known takeover-prone service (Heroku, GitHub Pages, Azure, S3 website endpoints, Netlify and others, see `dns_health/takeover.py`) that still exists is only **review**, because it is not exploitable while the resource is yours.
- **Mail pointers**: MX hosts, SPF present/multiple/roughly how many lookup mechanisms, DMARC present. This is a pointer, not a full mail audit.

Exit codes: `0` ok, `1` a finding at or above `--fail-on` (`info`, `warning` or `error`; default `error`), `2` usage error or the domain could not be resolved. `--no-tls` skips the one TLS connection to port 443.

## Measured result

Run against the author's own domain (DNS queries and a single TLS handshake; the zone is on Cloudflare):

```
$ python -m dns_health demarkstudio.ca --subdomains www,demo,marvin,admin
# DNS health: demarkstudio.ca

## Nameservers

- **OK** 2 nameservers: anton.ns.cloudflare.com, collins.ns.cloudflare.com
- **OK** Nameservers are on different networks: 108.162.194.0/24, 108.162.195.0/24, 162.159.38.0/24, 162.159.44.0/24, 172.64.34.0/24, 172.64.35.0/24, 2606:4700:50::/48, 2606:4700:58::/48, 2803:f800:50::/48, 2a06:98c1:50::/48
- **INFO** Single DNS provider: All nameservers are under cloudflare.com; fine for most sites, but a second provider survives a provider-wide outage

## SOA

- **INFO** Serial is not YYYYMMDDnn: 2416116835; a plain counter or timestamp is valid, the date format is only a convention
- **OK** SOA refresh in range: 10000 (recommended 1200-43200)
- **OK** SOA retry in range: 2400 (recommended 180-7200)
- **WARN** SOA expire outside recommended range: 604800; RFC 1912 recommends 1209600-2419200
- **OK** SOA minimum in range: 1800 (recommended 300-259200)

## Delegation (direct queries)

- **OK** Authoritative answer: anton.ns.cloudflare.com (108.162.195.175)
- **OK** Authoritative answer: anton.ns.cloudflare.com (162.159.44.175)
- **OK** Authoritative answer: anton.ns.cloudflare.com (172.64.35.175)
- **OK** Authoritative answer: collins.ns.cloudflare.com (108.162.194.226)
- **OK** Authoritative answer: collins.ns.cloudflare.com (162.159.38.226)
- **OK** Authoritative answer: collins.ns.cloudflare.com (172.64.34.226)
- **INFO** IPv6 not tested: this machine has no IPv6 route, so the 6 IPv6 nameserver address(es) could not be queried; run it from an IPv6 network to check them
- **OK** SOA serials agree: 2416116835

## DNSSEC

- **INFO** Zone is not signed: no DS at the parent and no DNSKEY; DNSSEC is optional

## CAA and certificate

- **INFO** No CAA records: adding `0 issue "pki.goog"` (your current certificate's CA) limits which CAs may issue certificates for the domain; on Cloudflare, adding any CAA record also makes Cloudflare add the records for the CAs its Universal SSL uses

## Addresses

- **OK** IPv4 present: 172.64.80.1
- **OK** IPv6 present: 2606:4700:130:436c:6f75:6466:6c61:7265

## TTL

- **INFO** A TTL low: 282s; fine while migrating, short for steady state
- **INFO** AAAA TTL low: 282s; fine while migrating, short for steady state
- **OK** MX TTL: 3600s
- **OK** NS TTL: 86400s

## www vs apex

- **OK** www and apex resolve to the same addresses: 172.64.80.1, 2606:4700:130:436c:6f75:6466:6c61:7265

## Wildcard

- **OK** No wildcard: a random label does not resolve

## Subdomains (dangling CNAME)

- **OK** www.demarkstudio.ca: no CNAME: not an alias, nothing dangling
- **OK** demo.demarkstudio.ca: no CNAME: not an alias, nothing dangling
- **OK** marvin.demarkstudio.ca: no CNAME: not an alias, nothing dangling
- **OK** admin.demarkstudio.ca: no CNAME: not an alias, nothing dangling

## Mail pointers (MX, SPF, DMARC)

- **OK** MX records: smtp.google.com
- **OK** SPF present: v=spf1 include:_spf.google.com ~all (about 1 lookup mechanisms; nested includes not followed)
- **OK** DMARC present: v=DMARC1; p=none; rua=mailto:hola@demarkstudio.ca

**Summary:** 0 error(s), 1 warning(s), 7 info, 25 ok
```

Reading it honestly:

- The zone is **not DNSSEC-signed** (info, as designed).
- **No CAA records**. The hint names the CA of the certificate actually served (Google Trust Services, `pki.goog`) instead of a generic example, and notes that Cloudflare adds its own CAs once any CAA record exists.
- The SOA `expire` is 604800 (7 days), below the RFC 1912 recommendation of 14-28 days. I believe this is Cloudflare's default for every zone, so I have not changed it.
- The machine I ran this on has no IPv6 route. The first version warned that the six IPv6 nameserver addresses "did not answer", which was about my network, not the domain. It now checks for a local IPv6 route first and reports those addresses as not tested (info). All six IPv4 addresses answered authoritatively with the same serial.
- `www`, `demo`, `marvin` and `admin` are all plain records, not CNAMEs, so nothing can dangle. `admin` does exist in DNS.

Tests (offline, DNS mocked):

```
python -m pytest -q -p no:cacheprovider --import-mode=importlib dns-health
80 passed in 0.12s
```

## Use it as a library

```python
from dns_health import run_checks, DnsResolver
from dns_health.report import to_markdown

report = run_checks("example.com", DnsResolver("1.1.1.1"), subdomains=["www", "shop"])
print(to_markdown(report))
report.failing("warning")   # True if any warning or error
```

`run_checks` only needs an object with `query(name, rtype, dnssec=False)` and `query_server(ip, name, rtype)`. Tests use `dns_health.testing.FakeResolver`, and the certificate lookup is a plain callable (`tls_issuer=lambda host: "Let's Encrypt (R11)"`), so no test touches the network.

## Limitations

- Provider diversity is a heuristic on the NS host name; `ns1.example.co.uk` and `ns2.example.co.uk` would both look like `co.uk`.
- The SPF lookup count covers the top-level record only; nested `include:` chains are not followed.
- Whether `www` redirects is HTTP, so it is not checked. Different addresses are reported as info.
- The certificate is read on port 443 of the apex only, and must validate normally.
- The parent-side delegation (NS at the registry) is not compared with the NS set in the zone.
- The takeover table is small and hand-made; it is a prompt to look, not a scanner.

## Install and test

```
pip install .            # console script: dns-health
python -m pytest -q -p no:cacheprovider --import-mode=importlib dns-health
```

Tests run offline. Python 3.10+.

## Author

Marvin Palencia, founder of [DeMark Studio](https://demarkstudio.ca), Miramichi, New Brunswick, Canada. Portfolio: [marvin.demarkstudio.ca](https://marvin.demarkstudio.ca)

MIT License.
