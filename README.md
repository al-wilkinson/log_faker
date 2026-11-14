# Synthetic API sign-in events for Microsoft Sentinel

Generates realistic sign-in events for a public-facing API integration host, for ingestion into a Microsoft Sentinel custom table through the Azure Monitor Logs Ingestion API.

The data contains about 24 hours of normal machine traffic plus a hidden password-spray scenario, so detections have something meaningful to find.

## Requirements

- Python 3.9 or later
- No third-party packages for the generator
- `requests` for the sender: `pip install -r requirements.txt`

## Generating events

```bash
python3 generate_events.py
```

Options:

| Option | Default | Description |
| --- | --- | --- |
| `--seed` | `42` | Random seed. The same seed gives the same shape of data; only the absolute times move. |
| `--hours` | `24` | Window length in hours, ending two minutes before now. Allowed range 3 to 47. |
| `--out-dir` | `.` | Where to write the output files. |

Example:

```bash
python3 generate_events.py --seed 7 --hours 36 --out-dir out
```

## Output

| File | Contents |
| --- | --- |
| `events.json` | Full event set as a JSON array, sorted by `EventTime` |
| `sample_events.json` | 15 representative events for the Azure portal custom table wizard |

The script also prints a summary: event counts per client and per result, and the exact UTC and Brisbane times of the hidden scenario.

### Event fields

`EventTime`, `ClientId`, `Username`, `SourceIP`, `UserAgent`, `AuthMethod`, `Endpoint`, `HttpMethod`, `Result`, `FailureReason`, `HttpStatus`, `CorrelationId`

## What the data contains

- **Baseline traffic** from 11 simulated clients using three patterns: scheduled pollers, business-hours usage (weighted by Brisbane time) and batch bursts.
- **Normal noise:** about 1.5% of baseline events fail (expired tokens, invalid keys or certificates, rate limiting).
- **A misconfigured client** (`partner-oscorp-01`) that fails steadily for the last six hours after a simulated secret rotation. Noisy, but not an attack.
- **A password spray** overnight in Brisbane time against `POST /v1/login`, from four IP addresses across 71 usernames, ending in one compromised account (`svc_legacyerp`) and follow-up logins from the attacker's IP.

## Important notes

- **Send the data soon after generating it.** Azure Monitor rejects or re-times records whose `TimeGenerated` is more than two days older than the time it receives them. Regenerate rather than sending an old file.
- **All times are UTC** in ISO 8601 format with millisecond precision.
- **IP addresses are from RFC 5737 documentation ranges**, so none are real and they won't geolocate.
- **No passwords or secrets** appear in any event.
- **`events.json` is over 1 MB**, the Logs Ingestion API per-request limit, so the sender must split it into batches.

## Sending events

`send_events.py` posts `events.json` to the Logs Ingestion API with plain `requests` calls. It authenticates as the `spn_integration_ingest` app registration using the client credentials flow.

### Azure prerequisites

- The `spn_integration_ingest` app registration with a client secret. It needs **no API permissions**.
- A custom table (default `ApiSignIn_CL`) and a DCR that maps `EventTime` to `TimeGenerated`.
- The **Monitoring Metrics Publisher** role for the app, assigned on the DCR itself.

### Configuration

Set these environment variables, or pass the matching options:

| Environment variable | Option | Value |
| --- | --- | --- |
| `AZURE_TENANT_ID` | `--tenant-id` | Directory (tenant) ID |
| `INGEST_CLIENT_ID` | `--client-id` | Application (client) ID of `spn_integration_ingest` |
| `INGEST_ENDPOINT` | `--endpoint` | DCE or DCR logs ingestion endpoint URL |
| `INGEST_DCR_ID` | `--dcr-id` | DCR immutable ID, starting `dcr-` |
| `INGEST_STREAM` | `--stream` | Stream name, default `Custom-ApiSignIn_CL` |
| `SENTINEL_INGEST` | (none) | Client secret value |

The secret is only read from the environment, never from the command line, so it doesn't end up in shell history or process listings. Don't commit it, or a `.env` file containing it, to this repository.

### Usage

```bash
python3 generate_events.py --out-dir out
python3 send_events.py --file out/events.json --dry-run   # check times and batches only
python3 send_events.py --file out/events.json --gzip
```

The sender:

- stops if any event is more than two days old, or more than a day in the future
- splits events into batches under the 1 MB per-request limit
- caches the access token and refreshes it before it expires, or once after a 401
- retries on 429 and 5xx responses with backoff, honouring `Retry-After`
- explains the common failures: 403 (role assignment missing or not yet effective) and 404 (wrong endpoint, DCR ID or stream)
- optionally gzip-compresses each request with `--gzip`

HTTP 204 means the API **accepted** a batch, not that it's stored. Allow a few minutes (longer for the first data in a new table), then check in Sentinel:

```kusto
ApiSignIn_CL
| summarize Events = count() by Result, bin(TimeGenerated, 1h)
```

If batches are accepted but no rows appear, check that the event fields match the DCR's stream declaration and look at the DCR's metrics in the Azure portal.
