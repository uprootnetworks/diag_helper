# Diag Helper

Check DNS resolution and HTTPS connectivity to uprootnetworks.com from a workstation. Requires Python 3.10+, Bash and `dig` on macOS or Linux.

## First run

```sh
python3 netcheck.py init
python3 netcheck.py diagnose
```

Initialization retrieves and verifies the release bootstrap, runs it, and installs the local diagnostic profile. The profile supplies the hostname, URL and timeout used by the checks. A fresh checkout must be initialized before diagnosis can run.

## Corporate TLS inspection

If your organization uses TLS inspection, provide its approved root certificate:

```sh
python3 netcheck.py --ca-file /path/to/approved-root.cer init
python3 netcheck.py --ca-file /path/to/approved-root.cer diagnose
```

This trusts the certificate for that process only. Certificate verification stays enabled.

## Output

`diagnostic-report.json` contains DNS results, the HTTPS result, workstation information and resolver settings. The report stays local. Handle it according to company policy. Existing reports are not overwritten.

## Setup troubleshooting

`python3 netcheck.py preflight` checks the bootstrap manifest, download and checksum without running initialization. Use `--ca-file` if needed. Checksum or connection failures leave the installation uninitialized.

## Tests

```sh
python3 -m unittest discover -s tests -v
```
