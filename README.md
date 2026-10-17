# Diag Helper

Troubleshoot HTTPS connectivity from the workstation where an application is failing. Diag Helper checks the requested sites and `https://uprootnetworks.com/` as a control, compares Python certificate trust with an optional approved organizational CA, and produces findings and a local report.

The normal workflow also submits a minimized summary to the [Uproot diagnostic intake](https://uprootnetworks.com/wp-json/agentdemo/v1/diagnostics) and returns a receipt. The summary contains the collection time, control-site DNS/TLS status and aggregate counts. Requested site names, resolved addresses, URL paths, certificate paths, proxy settings and error details remain in the local report. Workstation identity and resolver settings are not collected. The intake validates the summary and returns a receipt without storing its contents.

## Run

Requires Python 3.10 or later. No third-party packages are needed.

```sh
git clone https://github.com/uprootnetworks/diag_helper.git
cd diag_helper
python3 netcheck.py https://uprootnetworks.com/
```

For multiple affected services, pass their HTTPS URLs or hostnames:

```sh
python3 netcheck.py service.example.com https://another.example.com/health
```

Use targets you are authorized to check. URLs containing credentials, query parameters or fragments are rejected. HTTP redirects are reported without being followed.

For corporate TLS inspection, add the approved root certificate (PEM or DER):

```sh
python3 netcheck.py service.example.com --ca-file /path/to/approved-root.cer
```

The CA applies only to these processes. Current Python trust is sampled separately, so a difference between the two results can identify a certificate trust issue. Existing Python trust overrides are reported as flags. The tool does not change your trust store, proxy configuration, environment or application settings.

## Results

Each run creates `reports/<report-id>/diagnostic-report.json` and `support-summary.json`. Files are created with private permissions and existing runs are retained. The console prints findings and the support receipt. If submission fails, diagnostic findings and the report remain available locally.

The detailed report includes DNS resolution, a direct TCP connection attempt, repeated HTTPS HEAD requests, timings, HTTP status codes and error types. If HTTPS uses a proxy, its route can differ from the direct TCP attempt. HTTP 401/403/407 responses indicate access or authentication issues; an HTTP response alone does not establish that an application is healthy. The checks do not inspect authenticated application traffic.

Use `--samples 5` to take more samples or `--timeout 10` for a slower network. These are bounded connectivity checks rather than a continuous monitor. Python child processes perform the checks and submit the support summary over verified HTTPS.

To keep the support summary local, add `--local-only`:

```sh
python3 netcheck.py service.example.com --local-only
```

Exit code 0 means collection and the selected submission mode completed; connectivity problems can still appear in the findings. Exit code 1 indicates a setup or worker failure. Exit code 2 indicates support submission failed after diagnostics completed. An HTTP 429 from intake means its rate limit was reached; wait at least a minute before retrying.

## Tests

```sh
python3 -m unittest discover -s tests -v
```
