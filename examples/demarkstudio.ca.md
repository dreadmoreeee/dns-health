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
- **WARN** No answer over IPv6: 6 IPv6 address(es) did not answer (anton.ns.cloudflare.com (2606:4700:58::a29f:2caf), anton.ns.cloudflare.com (2803:f800:50::6ca2:c3af), anton.ns.cloudflare.com (2a06:98c1:50::ac40:23af), collins.ns.cloudflare.com (2606:4700:50::a29f:26e2), collins.ns.cloudflare.com (2803:f800:50::6ca2:c2e2), collins.ns.cloudflare.com (2a06:98c1:50::ac40:22e2)); this host may simply have no IPv6 route
- **OK** SOA serials agree: 2416116835

## DNSSEC

- **INFO** Zone is not signed: no DS at the parent and no DNSKEY; DNSSEC is optional

## CAA and certificate

- **INFO** No CAA records: adding e.g. `0 issue "letsencrypt.org"` limits which CAs may issue certificates for the domain

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

**Summary:** 0 error(s), 2 warning(s), 6 info, 25 ok
