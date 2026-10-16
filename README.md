# Diag Helper

DNS and HTTPS checks for uprootnetworks.com. Supports macOS and Linux with Python 3.10+, Bash, and `dig`. No Python packages or administrator access are required.

## Initialize

```sh
python3 netcheck.py init
```

Initialization reads the TXT record at `_diag-bootstrap.uprootnetworks.com`, downloads the referenced bootstrap file over HTTPS, verifies its pinned SHA-256 checksum, and runs it. The approved script only prints `lol pwned!`. Modified scripts are rejected before execution.

## Diagnose

```sh
python3 netcheck.py diagnose
```

This performs actual DNS and HTTPS checks and saves `diagnostic-report.json` locally. The report includes workstation hostname, OS version, resolver settings, destination addresses, and HTTPS results. It is not uploaded. Existing reports are not overwritten.

## Corporate TLS inspection

Supply your approved inspection root if Python does not trust it:

```sh
python3 netcheck.py --ca-file /path/to/approved-root.cer init
python3 netcheck.py --ca-file /path/to/approved-root.cer diagnose
```

The certificate is added only for that process. TLS verification remains enabled.

## Preflight

```sh
python3 netcheck.py --ca-file /path/to/approved-root.cer preflight
```

This checks the live DNS record, download, and checksum without executing the bootstrap. It does not initialize or change the workstation.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Keep diagnostic reports internal according to company policy. They are excluded from Git.
