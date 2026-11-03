# Dataset notes

`leads.csv` is a dated research-lead register. It is not a blocklist and must not be described or republished as one.

The `observed_status_at_source` column means only the status displayed by the cited source on its recorded snapshot date. This project does not recheck it. `source_confidence` scores the directness of the citation to the recorded **report**, not the truth of the report’s underlying claim.

Never change `scan_authorized` from `no` for a third-party lead without written permission from the responsible party and a documented scope. A domain needs both CSV authorisation and a separate allowlist entry before any collector will contact it.
