import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_lead_rows_are_non_runnable_and_unverified() -> None:
    with (ROOT / "data" / "leads.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows
    assert all(row["scan_authorized"] == "no" for row in rows)
    assert all(row["verification_status"] == "unverified_third_party_report" for row in rows)
    assert all(row["ownership_or_intent_claim"] == "none" for row in rows)


def test_each_lead_has_a_registered_source() -> None:
    with (ROOT / "data" / "source_register.csv").open(encoding="utf-8", newline="") as handle:
        source_ids = {row["source_id"] for row in csv.DictReader(handle)}
    with (ROOT / "data" / "leads.csv").open(encoding="utf-8", newline="") as handle:
        assert all(row["source_id"] in source_ids for row in csv.DictReader(handle))


def test_source_register_uses_direct_https_urls() -> None:
    with (ROOT / "data" / "source_register.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows
    assert all(row["source_url"].startswith("https://") for row in rows)
