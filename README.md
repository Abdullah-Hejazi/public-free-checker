# CutoverCheck free migration checker

Verify a supplied old-to-new URL mapping and export a timestamped evidence report.
Try the hosted five-pair checker at [cutovercheck.com](https://cutovercheck.com/).

This small Python CLI follows HTTP redirect chains, compares the observed destination with your
declared destination, and checks selected canonical/noindex metadata. It distinguishes failure,
review, and unknown results. It does not render JavaScript or certify a complete migration.

## Run locally

Requires Python 3.10 or newer. No third-party dependencies.

Create `mapping.csv`:

```csv
old_url,new_url,expected_status
https://your-old-domain.example/about,https://your-new-domain.example/about,301
```

Then run:

```sh
python3 scanner.py mapping.csv --output ./report --authorized
```

The CLI accepts 1–500 pairs. Only use `--authorized` for sites you own or are permitted to check.
Reports are written locally as HTML and JSON. Do not commit confidential URL maps or reports.
Requests are rate-limited per host and restricted to standard HTTP(S) ports and supplied hosts.
Private DNS destinations are rejected, and validated public IPs are pinned for each connection.
There is no remote telemetry, account, paid API, or model call in the CLI.

## Limits

- A pass applies only to the listed checks at the recorded time.
- No JavaScript rendering, robots.txt interpretation, actual indexation verification, or traffic guarantee.
- Protected, rate-limited, oversized, or timed-out responses need review and may be unknown.
- Canonical absence is a review item, not proof a page cannot be indexed.
- The CLI is not designed to be exposed directly as an unrestricted public web endpoint.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The software is developed and maintained with AI assistance. Report issues in this repository;
please remove private URLs and data from examples. Security-sensitive reports: support@cutovercheck.com.

The separate hosted seven-day package is planned and is not yet on sale. This CLI remains free.
