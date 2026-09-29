"""Small bundled table of services where a dangling CNAME is worth reviewing.

A CNAME to one of these is not a vulnerability by itself. It only becomes one
when the target resource no longer exists and someone else can claim it; that
needs a human check, so these are reported as 'review'. An NXDOMAIN target is
the only thing reported as an error.
"""

from __future__ import annotations

import re

# (suffix, service name)
SERVICES = (
    ("herokuapp.com", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("github.io", "GitHub Pages"),
    ("azurewebsites.net", "Azure App Service"),
    ("cloudapp.net", "Azure Cloud Services"),
    ("cloudapp.azure.com", "Azure VM"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("blob.core.windows.net", "Azure Blob Storage"),
    ("azureedge.net", "Azure CDN"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    ("netlify.app", "Netlify"),
    ("netlify.com", "Netlify"),
    ("surge.sh", "Surge"),
    ("ghost.io", "Ghost"),
    ("bitbucket.io", "Bitbucket Pages"),
    ("readme.io", "ReadMe"),
    ("helpscoutdocs.com", "Help Scout"),
    ("zendesk.com", "Zendesk"),
    ("myshopify.com", "Shopify"),
    ("statuspage.io", "Statuspage"),
    ("pantheonsite.io", "Pantheon"),
    ("unbouncepages.com", "Unbounce"),
    ("cargocollective.com", "Cargo"),
    ("wordpress.com", "WordPress.com"),
)

_S3_WEBSITE = re.compile(r"(^|\.)s3[.-]website[.-]([a-z0-9-]+\.)*amazonaws\.com(\.cn)?$")


def match_service(hostname: str) -> str | None:
    host = hostname.lower().rstrip(".")
    if _S3_WEBSITE.search(host):
        return "AWS S3 website"
    for suffix, name in SERVICES:
        if host == suffix or host.endswith("." + suffix):
            return name
    return None
