# Kenya website reconnaissance research kit

This starter kit supports careful, defensible research on Kenya-related website leads and a **low-impact, authorization-gated metadata collector**. It is designed for triage and recordkeeping—not for finding vulnerabilities or deciding whether a person or organisation has done anything wrong.

## Safety and research rules

- Every domain in `data/leads.csv` is an **unverified third-party report or historic research lead**. A threat-feed entry can describe a compromised site, shared-hosting artefact, stale record, or false positive. It is never proof of ownership, intent, criminality, or current malicious activity.
- The default scan input contains no runnable target. Threat-feed leads are deliberately marked `scan_authorized=no` and are not allowlisted.
- Only assess domains you own or have clear written permission to assess. Before the runner will make a request, a domain must be in both the input CSV with `scan_authorized=yes` and `config/allowlist.txt`; you must also provide the explicit command-line acknowledgement.
- Create `config/STOP` (an empty file is enough) to stop the runner before the next target/action. Do not remove it until you have reviewed the scope.
- The collector makes, at most, one HTTPS `HEAD /` request (no redirect following and no response body download), one TLS handshake, ordinary DNS lookups, and one RDAP lookup per allowed target. It does not crawl, enumerate paths/subdomains, submit forms, authenticate, exploit, fuzz, brute-force, use a proxy, or access non-public data.
- “Passive-only” is often used loosely. DNS, a TLS handshake, an HTTP `HEAD`, and RDAP lookups still contact network services. This kit keeps them deliberately low-impact and transparent; use a purely offline dataset workflow if no network contact is permitted.

## Contents

| Path | Purpose |
| --- | --- |
| `data/leads.csv` | Kenya-related historic/reporting leads, with source and evidence fields |
| `data/leads_template.csv` | Blank rows for new leads |
| `data/comparison_sites_template.csv` | A blank template for authorised, legitimate comparison sites—no invented targets |
| `data/targets_to_scan.csv` | Empty-by-default CSV-driven scan scope |
| `data/source_register.csv` | Direct, reviewable source URLs and limits on what each source establishes |
| `config/allowlist.txt` | Second approval gate for targets |
| `config/STOP` | Emergency stop file; create it to halt collection |
| `scripts/` | Collector runner plus focused, equally gated wrappers |
| `reports/` | Illustrative, non-live report format |
| `tests/` | Offline unit tests for scope and parser safeguards |

## Quick start

1. Create an isolated environment and install dependencies:

   ```bash
   python -m venv .venv
   . .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Obtain written permission for each target. Copy the target into `data/targets_to_scan.csv`, set `scan_authorized` to `yes`, and add the same bare domain to `config/allowlist.txt`. Never copy a threat-feed lead into the allowlist merely because it appears in `leads.csv`.

3. Confirm there is no `config/STOP` file, then run a small approved scope:

   ```bash
   python scripts/run_collection.py \
     --input data/targets_to_scan.csv \
     --allowlist config/allowlist.txt \
     --output reports/local/collection.json \
     --delay-seconds 5 \
     --max-targets 12 \
     --i-own-or-have-written-permission YES
   ```

   The runner refuses delays under five seconds, scopes above 25 targets, targets outside the allowlist, targets not explicitly authorised in the CSV, malformed domains, and domains resolving to non-public addresses.

4. Review the JSON and its adjacent `.summary.csv`. Results are observations from the collection time, not a security rating or proof that a site is safe/unsafe.

## CSV workflow

`leads.csv` separates the strength of a source from the truth of its claim:

- `source_confidence` means only how directly the cited URL supports the recorded **report**.
- `verification_status` remains `unverified_third_party_report` until independently investigated.
- `ownership_or_intent_claim` is intentionally `none`; the dataset makes none.
- `evidence_url` should point to the report itself, not a copy of a target website.

Use `leads_template.csv` for any new lead. Record the original wording faithfully, timestamp the source snapshot, explain corroboration or conflicts, and avoid personal data. `comparison_sites_template.csv` is for organisations/sites your team has legitimately selected and is never populated with invented “safe” sites.

## Command-line tools

All tools require the same three safeguards: the permission acknowledgement, CSV `scan_authorized=yes`, and an allowlist match.

- `scripts/run_collection.py` — DNS, TLS, a single `HEAD /`, and RDAP in one rate-limited run.
- `scripts/check_headers.py` — HTTPS response-header observation only.
- `scripts/tls_metadata.py` — TLS certificate metadata only.
- `scripts/dns_rdap_metadata.py` — DNS and RDAP metadata only.

Each wrapper accepts `--help`. They make no network call unless all safeguards pass. Keep target lists narrow and wait for written approval where a programme or contract requires it.

## Interpreting observations

Missing headers, an expired certificate, DNS records, or RDAP fields are limited technical observations. They can be caused by a CDN, a maintenance state, delegated administration, a legacy application, a scanning block, or collection error. Do not use a single observation to label a site, report a person, or make a transaction decision. Preserve the source URL and timestamp, seek corroboration, and follow your organisation’s incident/reporting process.

For suspected phishing or online fraud affecting Kenya, preserve only necessary evidence and use an appropriate official reporting path such as the National KE-CIRT/CC guidance listed in `data/source_register.csv`. Do not contact alleged operators or interact with content/forms as part of this kit.

## Tests

Run offline tests with:

```bash
pytest -q
```

## Limitations

This is a starter kit, not a vulnerability scanner, malware detector, legal determination, or monitoring service. Threat intelligence changes quickly; keep snapshots dated, review source terms before automated use, and do not re-publish the lead list as a list of “scam websites.”
