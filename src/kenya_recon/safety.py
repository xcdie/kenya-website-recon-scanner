"""Scope controls shared by every network-capable command.

These checks reduce accidental misuse; they do not replace written authorisation,
organisational policy, or a formal engagement scope.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path


class SafetyError(ValueError):
    """Raised before a network action when the approved scope is not satisfied."""


_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str:
    """Accept a bare DNS hostname only; reject URLs, paths, IP literals and wildcards."""
    domain = value.strip().lower().rstrip(".")
    if not domain or "://" in domain or "/" in domain or "@" in domain:
        raise SafetyError("target must be a bare domain, not a URL, path, or credential")
    if len(domain) > 253 or "." not in domain:
        raise SafetyError("target must be a plausible multi-label domain")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise SafetyError("IP literals are not accepted as scan targets")
    labels = domain.split(".")
    if any(not _LABEL.fullmatch(label) for label in labels):
        raise SafetyError("target contains an invalid DNS label")
    return domain


def load_allowlist(path: Path) -> set[str]:
    """Read normalised bare domains, ignoring blank lines and comments."""
    if not path.exists():
        raise SafetyError(f"allowlist not found: {path}")
    entries: set[str] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        value = raw.split("#", maxsplit=1)[0].strip()
        if not value:
            continue
        try:
            entries.add(normalize_domain(value))
        except SafetyError as error:
            raise SafetyError(f"invalid allowlist entry on line {number}: {error}") from error
    return entries


def stop_requested(stop_file: Path) -> bool:
    """An existing STOP file is an immediate, operator-controlled halt signal."""
    return stop_file.exists()


def require_authorised_target(
    domain: str,
    *,
    scan_authorized: str,
    allowlist: set[str],
    stop_file: Path,
) -> str:
    """Require CSV consent, allowlist membership, and no emergency stop file."""
    if stop_requested(stop_file):
        raise SafetyError(f"STOP file exists: {stop_file}; no network action will be taken")
    normalised = normalize_domain(domain)
    if scan_authorized.strip().lower() != "yes":
        raise SafetyError(f"{normalised}: CSV scan_authorized must be exactly 'yes'")
    if normalised not in allowlist:
        raise SafetyError(f"{normalised}: absent from the allowlist")
    return normalised


def public_addresses(domain: str, port: int = 443) -> list[str]:
    """Resolve and allow only globally routable address records.

    This blocks obvious SSRF-style targets such as loopback, link-local and RFC1918
    addresses. The returned address is pinned by the HTTP/TLS collector.
    """
    try:
        records = socket.getaddrinfo(
            domain, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except socket.gaierror as error:
        raise SafetyError(f"{domain}: DNS resolution failed ({error})") from error
    addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise SafetyError(f"{domain}: no address records returned")
    non_public = [address for address in addresses if not ipaddress.ip_address(address).is_global]
    if non_public:
        raise SafetyError(
            f"{domain}: refusing target because it resolves to non-public address(es): "
            + ", ".join(non_public)
        )
    return addresses
