from pathlib import Path

import dns.resolver

from kenya_recon.collectors import dns_metadata, parse_http_headers, security_header_observations


def test_parse_http_headers_does_not_include_body() -> None:
    raw = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\nX-Test: one\r\n\r\nbody"
    status, headers = parse_http_headers(raw)
    assert status == 200
    assert headers == {"content-security-policy": "default-src 'self'", "x-test": "one"}


def test_parse_http_headers_accepts_lf_only_newlines() -> None:
    raw = b"HTTP/1.1 204 No Content\nContent-Type: text/plain\nX-Trace: abc\n\nbody"
    status, headers = parse_http_headers(raw)
    assert status == 204
    assert headers == {"content-type": "text/plain", "x-trace": "abc"}


def test_dns_metadata_handles_no_answer(monkeypatch) -> None:
    class FakeResolver:
        def __init__(self, *args, **kwargs) -> None:
            self.timeout = 0.0
            self.lifetime = 0.0

        def resolve(self, domain: str, record_type: str, raise_on_no_answer: bool = False):
            raise dns.resolver.NoAnswer

    monkeypatch.setattr("kenya_recon.collectors.dns.resolver.Resolver", FakeResolver)

    result = dns_metadata("example.co.ke", timeout=1.0, stop_file=Path("/tmp/STOP"))
    assert result["records"]["A"] == {"error": "NoAnswer"}


def test_security_header_observations_are_presence_only() -> None:
    observations = security_header_observations({"strict-transport-security": "max-age=1"})
    assert observations["HSTS"] == "present"
    assert observations["Content-Security-Policy"] == "not_observed"
