# Network Triage

Collect DNS and HTTPS diagnostics for uprootnetworks.com, including the workstation's resolver settings. Python 3.10+; no third-party packages or administrator access required.

## Run

```sh
python3 netcheck.py diagnose
```

This checks website reachability and creates `diagnostic-report.json` in the current directory. The report includes the computer's hostname, OS version, resolver configuration, resolved addresses, and HTTPS result. It does not read credentials, browser data, or customer records.

If the connection fails, retrieve the troubleshooting instructions:

```sh
python3 netcheck.py guidance
```

## Corporate certificate inspection

If Python doesn't trust your organization's inspection certificate, supply your approved root certificate. Certificate verification stays enabled. For example:

```sh
python3 netcheck.py --ca-file /path/to/approved-root.cer diagnose
python3 netcheck.py --ca-file /path/to/approved-root.cer guidance
```

The certificate is added for this process only. The operating system trust store is not changed.

## Privacy

`diagnose` writes a local report and sends ordinary DNS and HTTPS requests. `guidance` downloads text and displays it. Neither command uploads the diagnostic report. Decide whether external troubleshooting instructions are appropriate before acting on them.

Diagnostic reports can reveal internal hostnames, DNS servers, and search domains. Handle them according to company policy. The generated report is excluded from Git.

## Tests

```sh
python3 -m unittest discover -s tests -v
```
