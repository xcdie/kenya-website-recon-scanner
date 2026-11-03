from pathlib import Path

import pytest

from kenya_recon.safety import SafetyError, load_allowlist, normalize_domain, require_authorised_target


def test_normalize_domain_accepts_bare_hostname() -> None:
    assert normalize_domain(" Example.Co.KE. ") == "example.co.ke"


@pytest.mark.parametrize("value", ["https://example.co.ke", "example.co.ke/path", "127.0.0.1", "*.example.co.ke", "singlelabel"])
def test_normalize_domain_rejects_non_bare_or_unsafe_targets(value: str) -> None:
    with pytest.raises(SafetyError):
        normalize_domain(value)


def test_allowlist_normalises_comments_and_domains(tmp_path: Path) -> None:
    allowlist = tmp_path / "allowlist.txt"
    allowlist.write_text("# approved scope\nExample.CO.KE. # ticket-1\n", encoding="utf-8")
    assert load_allowlist(allowlist) == {"example.co.ke"}


def test_target_needs_csv_authorisation_allowlist_and_no_stop(tmp_path: Path) -> None:
    stop_file = tmp_path / "STOP"
    approved = require_authorised_target(
        "example.co.ke", scan_authorized="yes", allowlist={"example.co.ke"}, stop_file=stop_file
    )
    assert approved == "example.co.ke"
    with pytest.raises(SafetyError, match="scan_authorized"):
        require_authorised_target(
            "example.co.ke", scan_authorized="no", allowlist={"example.co.ke"}, stop_file=stop_file
        )
    with pytest.raises(SafetyError, match="absent from the allowlist"):
        require_authorised_target(
            "example.co.ke", scan_authorized="yes", allowlist=set(), stop_file=stop_file
        )
    stop_file.touch()
    with pytest.raises(SafetyError, match="STOP file exists"):
        require_authorised_target(
            "example.co.ke", scan_authorized="yes", allowlist={"example.co.ke"}, stop_file=stop_file
        )
