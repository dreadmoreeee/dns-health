"""Read the issuer of the certificate a host serves on port 443."""

from __future__ import annotations

import socket
import ssl

# Issuer organisation (lower case substring) -> CAA issuer domains that authorise it.
ISSUER_TO_CAA = {
    "let's encrypt": ("letsencrypt.org",),
    "google trust services": ("pki.goog",),
    "digicert": ("digicert.com",),
    "sectigo": ("sectigo.com",),
    "comodo": ("sectigo.com", "comodoca.com"),
    "zerossl": ("sectigo.com", "zerossl.com"),
    "globalsign": ("globalsign.com",),
    "amazon": ("amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"),
    "godaddy": ("godaddy.com",),
    "go daddy": ("godaddy.com",),
    "ssl.com": ("ssl.com",),
    "buypass": ("buypass.com",),
    "entrust": ("entrust.net",),
}


def caa_domains_for_issuer(issuer: str) -> tuple[str, ...] | None:
    low = issuer.lower()
    for key, domains in ISSUER_TO_CAA.items():
        if key in low:
            return domains
    return None


def fetch_issuer(host: str, port: int = 443, timeout: float = 5.0) -> str:
    """Return 'organisation (CN)' of the leaf certificate's issuer.

    The certificate is verified normally; a failed handshake raises OSError.
    """
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    fields = {}
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            fields[key] = value
    org = fields.get("organizationName", "")
    cn = fields.get("commonName", "")
    return f"{org} ({cn})" if org and cn else (org or cn)
