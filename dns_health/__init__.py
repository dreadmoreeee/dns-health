"""DNS health report for a domain."""

from .checks import run_checks
from .model import Answer, Finding, Report, RR
from .resolver import DnsResolver, Resolver

__all__ = ["run_checks", "Answer", "Finding", "Report", "RR", "DnsResolver", "Resolver"]
__version__ = "1.0.0"
