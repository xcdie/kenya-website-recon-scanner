"""Small, no-crawl collectors for public website metadata."""

from __future__ import annotations

import csv
import datetime as dt
import json
import socket
import ssl
from pathlib import Path
from typing import Any
from urllib.parse import quote

import dns.resolver
import requests

from .safety import SafetyError, public_addresses, stop_requested

USER_AGENT = "KenyaReconStarter/0.1 (authorised metadata collection; no crawl)"
RDAP_ENDPOINT = "https://rdap.org/domain/"
MAX_HEADER_BYTES = 16_384


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def parse_http_headers(raw: bytes) -> tuple[int | None, dict[str, str]]:
    """Parse only a bounded HTTP response header block; intentionally ignore bodies."""
    if b"\r\n\r\n" in raw:
        header_block = raw.split(b"\r\n\r\n", maxsplit=1)[0]
    elif b"\n\n" in raw:
        header_block = raw.split(b"\n\n", maxsplit=1)[0]
    else:
        header_block = raw

    normalized = header_block.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    lines = normalized.decode("iso-8859-1", errors="replace").split("\n")
    status: int | None = None
    if lines and len(lines[0].split()) >= 2:
        try:
            status = int(lines[0].split()[1])
        except ValueError:
            pass
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", maxsplit=1)
        headers[key.strip().lower()] = value.strip()
    return status, headers


def security_header_observations(headers: dict[str, str]) -> dict[str, str]:
    """Report presence only; this is not a quality grade or vulnerability finding."""
    expected = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "Content-Security-Policy",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
        "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
    }
    return {label: ("present" if name in headers else "not_observed") for name, label in expected.items()}


def _certificate_summary(certificate: dict[str, Any]) -> dict[str, Any]:
    def flatten_name(value: Any) -> list[str]:
        result: list[str] = []
        for item in value or ():
            for key, name in item:
                result.append(f"{key}={name}")
        return result

    return {
        "subject": flatten_name(certificate.get("subject")),
        "issuer": flatten_name(certificate.get("issuer")),
        "serial_number": certificate.get("serialNumber"),
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
        "subject_alt_names": [
            value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"
        ],
    }


def tls_certificate_metadata(
    domain: str, *, addresses: list[str], timeout: float, stop_file: Path
) -> dict[str, Any]:
    """Perform one certificate-validated TLS handshake and send no HTTP request."""
    if stop_requested(stop_file):
        raise SafetyError("STOP file exists before TLS metadata collection")
    address = addresses[0]
    context = ssl.create_default_context()
    try:
        with socket.create_connection((address, 443), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=domain) as tls_socket:
                return {
                    "attempted": True,
                    "address": address,
                    "protocol": tls_socket.version(),
                    "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                    "certificate": _certificate_summary(tls_socket.getpeercert()),
                    "http_request_sent": False,
                }
    except (OSError, ssl.SSLError) as error:
        return {
            "attempted": True,
            "address": address,
            "error": f"{type(error).__name__}: {error}",
            "http_request_sent": False,
        }


def https_head_and_tls(
    domain: str, *, addresses: list[str], timeout: float, stop_file: Path
) -> dict[str, Any]:
    """Use one pinned-address TLS connection and one HEAD / request.

    The request has no form data, does not follow redirects and reads at most the
    first bounded header block. It deliberately does not fetch an HTTP response body.
    """
    if stop_requested(stop_file):
        raise SafetyError("STOP file exists before HTTPS/TLS collection")
    address = addresses[0]
    context = ssl.create_default_context()
    request = (
        f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {USER_AGENT}\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    try:
        with socket.create_connection((address, 443), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=domain) as tls_socket:
                tls_socket.settimeout(timeout)
                protocol = tls_socket.version()
                cipher = tls_socket.cipher()
                certificate = _certificate_summary(tls_socket.getpeercert())
                if stop_requested(stop_file):
                    raise SafetyError("STOP file exists before HTTP header request")
                tls_socket.sendall(request)
                raw = b""
                while b"\r\n\r\n" not in raw and len(raw) < MAX_HEADER_BYTES:
                    chunk = tls_socket.recv(min(4096, MAX_HEADER_BYTES - len(raw)))
                    if not chunk:
                        break
                    raw += chunk
    except (OSError, ssl.SSLError) as error:
        return {
            "attempted": True,
            "address": address,
            "error": f"{type(error).__name__}: {error}",
        }
    status, headers = parse_http_headers(raw)
    return {
        "attempted": True,
        "address": address,
        "tls": {"protocol": protocol, "cipher": cipher[0] if cipher else None, "certificate": certificate},
        "http_head": {
            "status": status,
            "headers": headers,
            "security_header_presence": security_header_observations(headers),
            "bytes_read": len(raw),
            "redirects_followed": 0,
            "response_body_downloaded": False,
        },
    }


def dns_metadata(domain: str, *, timeout: float, stop_file: Path) -> dict[str, Any]:
    """Ask the configured recursive resolver for a short, fixed set of public records."""
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout
    result: dict[str, Any] = {"attempted_record_types": ["A", "AAAA", "MX", "NS"], "records": {}}
    for record_type in result["attempted_record_types"]:
        if stop_requested(stop_file):
            raise SafetyError("STOP file exists during DNS collection")
        try:
            answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)
            result["records"][record_type] = [answer.to_text() for answer in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ) as error:
            result["records"][record_type] = {"error": type(error).__name__}
        except dns.resolver.YXDOMAIN:
            result["records"][record_type] = {"error": "YXDOMAIN"}
        except dns.exception.DNSException as error:
            result["records"][record_type] = {"error": type(error).__name__}
    return result


def rdap_metadata(domain: str, *, timeout: float, stop_file: Path) -> dict[str, Any]:
    """Fetch a public RDAP record from a fixed endpoint; retain a minimal subset only."""
    if stop_requested(stop_file):
        raise SafetyError("STOP file exists before RDAP collection")
    try:
        with requests.Session() as session:
            # Do not inherit an ambient HTTP proxy; the only outbound endpoint here
            # is the fixed public RDAP service named above.
            session.trust_env = False
            response = session.get(
                RDAP_ENDPOINT + quote(domain, safe=""),
                headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"},
                timeout=timeout,
                allow_redirects=False,
            )
    except requests.RequestException as error:
        return {"attempted": True, "endpoint": "rdap.org", "error": f"{type(error).__name__}: {error}"}
    if not response.ok:
        return {"attempted": True, "endpoint": "rdap.org", "http_status": response.status_code}
    try:
        payload = response.json()
    except ValueError:
        return {"attempted": True, "endpoint": "rdap.org", "http_status": response.status_code, "error": "invalid_json"}
    events = {
        event.get("eventAction"): event.get("eventDate")
        for event in payload.get("events", [])
        if event.get("eventAction") in {"registration", "expiration", "last changed"}
    }
    return {
        "attempted": True,
        "endpoint": "rdap.org",
        "http_status": response.status_code,
        "handle": payload.get("handle"),
        "ldh_name": payload.get("ldhName"),
        "status": payload.get("status", []),
        "events": events,
        "nameservers": [item.get("ldhName") for item in payload.get("nameservers", []) if item.get("ldhName")],
        "notice_titles": [
            notice.get("title") for notice in payload.get("notices", []) if notice.get("title")
        ],
        "personal_data_collected": False,
    }


def collect_site(domain: str, *, timeout: float, stop_file: Path) -> dict[str, Any]:
    """Collect a fixed, low-impact metadata set for an already authorised target."""
    if stop_requested(stop_file):
        raise SafetyError("STOP file exists before collection")
    addresses = public_addresses(domain)
    result: dict[str, Any] = {
        "domain": domain,
        "collected_at_utc": utc_now(),
        "collection_limits": {
            "http": "one HTTPS HEAD /; no redirects; no response body",
            "tls": "one standard certificate-validated handshake",
            "dns": "A, AAAA, MX and NS only",
            "rdap": "one public RDAP lookup; minimal fields retained",
        },
        "resolved_public_addresses": addresses,
    }
    result["dns"] = dns_metadata(domain, timeout=timeout, stop_file=stop_file)
    result["https_tls"] = https_head_and_tls(
        domain, addresses=addresses, timeout=timeout, stop_file=stop_file
    )
    result["rdap"] = rdap_metadata(domain, timeout=timeout, stop_file=stop_file)
    return result


def load_targets(path: Path) -> list[dict[str, str]]:
    """Read a known CSV schema without treating blank/template rows as targets."""
    required = {"target_id", "domain", "scan_authorized", "permission_reference", "purpose"}
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
            raise SafetyError("input CSV lacks required target columns")
        return [row for row in reader if (row.get("domain") or "").strip()]


def write_report(payload: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_path = output.with_suffix(".summary.csv")
    rows: list[dict[str, str]] = []
    for item in payload.get("results", []):
        if "domain" not in item:
            continue
        head = item.get("https_tls", {}).get("http_head", {})
        rows.append(
            {
                "domain": item["domain"],
                "collected_at_utc": item.get("collected_at_utc", ""),
                "http_head_status": str(head.get("status", "")),
                "hsts": head.get("security_header_presence", {}).get("HSTS", ""),
                "csp": head.get("security_header_presence", {}).get("Content-Security-Policy", ""),
                "collection_error": item.get("error", ""),
            }

            
        )
    with summary_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["domain", "collected_at_utc", "http_head_status", "hsts", "csp", "collection_error"])
        writer.writeheader()
        writer.writerows(rows)
