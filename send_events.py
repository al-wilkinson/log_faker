#!/usr/bin/env python3
"""
Send events.json to a Microsoft Sentinel custom table through the Azure Monitor
Logs Ingestion API, using plain HTTP requests (no Azure SDK).

Authentication uses the OAuth 2.0 client credentials flow for the
spn_integration_ingest app registration. The app needs the Monitoring Metrics
Publisher role on the data collection rule (DCR); it needs no API permissions.

Configuration (environment variables, or the matching command-line options):
  AZURE_TENANT_ID      Directory (tenant) ID                       --tenant-id
  INGEST_CLIENT_ID     Application (client) ID of the app          --client-id
  INGEST_ENDPOINT      DCE or DCR logs ingestion endpoint URL      --endpoint
  INGEST_DCR_ID        DCR immutable ID (starts with "dcr-")       --dcr-id
  INGEST_STREAM        Stream name (default Custom-ApiSignIn_CL)   --stream
  SENTINEL_INGEST      Client secret value (environment variable only)

The secret is deliberately not accepted as a command-line option, because
command lines end up in shell history and process listings.
"""

import argparse
import gzip
import json
import os
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

UTC = timezone.utc
BRISBANE = timezone(timedelta(hours=10), "AEST")

MONITOR_SCOPE = "https://monitor.azure.com/.default"
API_VERSION = "2023-01-01"
MAX_BATCH_BYTES = 950_000      # API limit is 1 MB (1,048,576 bytes); keep a margin
MAX_RETRIES = 5
TOKEN_REFRESH_MARGIN = 300     # refresh the token when under 5 minutes remain

MAX_AGE = timedelta(days=2)    # older records are dropped or re-timed by Azure Monitor
WARN_AGE = timedelta(hours=36)
MAX_FUTURE = timedelta(days=1)

DEFAULT_STREAM = "Custom-ApiSignIn_CL"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------


def parse_time(value):
    # fromisoformat handles a trailing 'Z' from Python 3.11; replace it for older versions.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def both_times(t):
    return f"{t:%Y-%m-%d %H:%M:%S} UTC ({t.astimezone(BRISBANE):%Y-%m-%d %H:%M} Brisbane)"


def check_times(events, field):
    """Stop if any event is too old or too far in the future to ingest correctly."""
    try:
        times = [parse_time(e[field]) for e in events]
    except (KeyError, ValueError) as ex:
        sys.exit(f"Every event needs a valid ISO 8601 '{field}' value: {ex}")

    now = datetime.now(UTC)
    oldest, newest = min(times), max(times)
    print(f"Event times:  {both_times(oldest)}")
    print(f"          to  {both_times(newest)}")

    if now - oldest > MAX_AGE:
        sys.exit("Some events are more than two days old, so Azure Monitor would drop or "
                 "re-time them. Run generate_events.py again, then send straight away.")
    if newest - now > MAX_FUTURE:
        sys.exit("Some events are more than a day in the future. Check the clock on this machine.")
    if now - oldest > WARN_AGE:
        print(f"Warning: the oldest event is {(now - oldest).total_seconds() / 3600:.1f} hours "
              "old. Send soon, or regenerate.")


def make_batches(events):
    """Split events into JSON arrays that each stay under MAX_BATCH_BYTES."""
    batches, current, size = [], [], 2          # 2 bytes for the enclosing [ ]
    for e in events:
        item_size = len(json.dumps(e, separators=(",", ":")).encode("utf-8")) + 1   # + comma
        if item_size + 2 > MAX_BATCH_BYTES:
            sys.exit(f"A single event is larger than the per-request limit: {e.get('CorrelationId')}")
        if current and size + item_size > MAX_BATCH_BYTES:
            batches.append(current)
            current, size = [], 2
        current.append(e)
        size += item_size
    if current:
        batches.append(current)
    return batches

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


class TokenProvider:
    """Client credentials token for Azure Monitor, cached until near expiry."""

    def __init__(self, session, tenant_id, client_id, secret):
        self.session = session
        self.url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        self.form = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
            "scope": MONITOR_SCOPE,
        }
        self.token = None
        self.expires_at = 0.0

    def get(self, force=False):
        if not force and self.token and time.time() < self.expires_at - TOKEN_REFRESH_MARGIN:
            return self.token

        resp = self.session.post(self.url, data=self.form, timeout=30)
        if resp.status_code != 200:
            detail = resp.text[:300]
            try:
                err = resp.json()
                # Entra error descriptions start with an AADSTS code, e.g. AADSTS7000215 (invalid secret).
                detail = f"{err.get('error')}: {err.get('error_description', '').splitlines()[0]}"
            except ValueError:
                pass
            sys.exit(f"Token request failed (HTTP {resp.status_code}). {detail}")

        body = resp.json()
        self.token = body["access_token"]
        self.expires_at = time.time() + int(body.get("expires_in", 3599))
        print(f"Token acquired, valid for {int(body.get('expires_in', 3599)) // 60} minutes.")
        return self.token

# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------


def backoff(attempt, retry_after=None):
    if retry_after:
        try:
            return min(float(retry_after), 120.0)
        except ValueError:
            pass
    return min(60.0, 2 ** attempt) + random.uniform(0, 1)


def send_batch(session, url, tokens, batch, use_gzip, label):
    body = json.dumps(batch, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if use_gzip:
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"

    refreshed = False
    attempt = 0
    while attempt < MAX_RETRIES:
        attempt += 1
        headers["Authorization"] = f"Bearer {tokens.get()}"
        try:
            resp = session.post(url, data=body, headers=headers, timeout=60)
        except requests.RequestException as ex:
            wait = backoff(attempt)
            print(f"  {label}: network error ({ex.__class__.__name__}); retrying in {wait:.0f}s")
            time.sleep(wait)
            continue

        status = resp.status_code
        if status == 204:
            request_id = resp.headers.get("x-ms-request-id", "")
            print(f"  {label}: accepted ({len(batch)} events, {len(body):,} bytes) {request_id}")
            return

        if status == 401 and not refreshed:
            print(f"  {label}: 401 Unauthorized; refreshing the token and retrying once")
            tokens.get(force=True)
            refreshed = True
            attempt -= 1          # a token refresh doesn't count as a retry
            continue

        if status == 403:
            sys.exit(f"  {label}: 403 Forbidden. The app can sign in but isn't allowed to send to "
                     "this DCR. Check it has Monitoring Metrics Publisher on the DCR itself. A new "
                     "role assignment can take several minutes to take effect.\n"
                     f"  Response: {resp.text[:300]}")

        if status == 404:
            sys.exit(f"  {label}: 404 Not Found. Check the endpoint, the DCR immutable ID and the "
                     f"stream name.\n  Response: {resp.text[:300]}")

        if status == 413:
            sys.exit(f"  {label}: 413 Payload too large. Reduce MAX_BATCH_BYTES.")

        if status == 429 or status >= 500:
            wait = backoff(attempt, resp.headers.get("Retry-After"))
            print(f"  {label}: HTTP {status}; retrying in {wait:.0f}s (attempt {attempt}/{MAX_RETRIES})")
            time.sleep(wait)
            continue

        sys.exit(f"  {label}: HTTP {status}. Response: {resp.text[:500]}")

    sys.exit(f"  {label}: giving up after {MAX_RETRIES} attempts.")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Send events to Microsoft Sentinel through the Logs Ingestion API.")
    parser.add_argument("--file", default="events.json", help="JSON array of events (default events.json)")
    parser.add_argument("--tenant-id", default=os.environ.get("AZURE_TENANT_ID"))
    parser.add_argument("--client-id", default=os.environ.get("INGEST_CLIENT_ID"))
    parser.add_argument("--endpoint", default=os.environ.get("INGEST_ENDPOINT"))
    parser.add_argument("--dcr-id", default=os.environ.get("INGEST_DCR_ID"))
    parser.add_argument("--stream", default=os.environ.get("INGEST_STREAM", DEFAULT_STREAM))
    parser.add_argument("--time-field", default="EventTime",
                        help="field the DCR maps to TimeGenerated (default EventTime)")
    parser.add_argument("--gzip", action="store_true", help="gzip-compress each request body")
    parser.add_argument("--dry-run", action="store_true",
                        help="check the file and show the batches without authenticating or sending")
    args = parser.parse_args()

    with open(args.file, encoding="utf-8") as f:
        events = json.load(f)
    if not isinstance(events, list) or not events:
        sys.exit(f"{args.file} must contain a non-empty JSON array.")

    print(f"File:         {args.file} ({len(events)} events)")
    check_times(events, args.time_field)
    batches = make_batches(events)
    print(f"Batches:      {len(batches)} (largest {max(len(b) for b in batches)} events)")

    if args.dry_run:
        print("Dry run: nothing sent.")
        return

    secret = os.environ.get("SENTINEL_INGEST")
    missing = [name for name, value in [
        ("AZURE_TENANT_ID or --tenant-id", args.tenant_id),
        ("INGEST_CLIENT_ID or --client-id", args.client_id),
        ("INGEST_ENDPOINT or --endpoint", args.endpoint),
        ("INGEST_DCR_ID or --dcr-id", args.dcr_id),
        ("SENTINEL_INGEST (environment variable)", secret),
    ] if not value]
    if missing:
        sys.exit("Missing configuration:\n  " + "\n  ".join(missing))
    if not args.dcr_id.startswith("dcr-"):
        sys.exit("The DCR ID should be the immutable ID from the DCR's JSON view, starting 'dcr-'.")

    url = (f"{args.endpoint.rstrip('/')}/dataCollectionRules/{args.dcr_id}"
           f"/streams/{args.stream}?api-version={API_VERSION}")
    print(f"Target:       {url}")

    with requests.Session() as session:
        tokens = TokenProvider(session, args.tenant_id, args.client_id, secret)
        tokens.get()
        for i, batch in enumerate(batches, start=1):
            send_batch(session, url, tokens, batch, args.gzip, f"Batch {i}/{len(batches)}")

    table = args.stream.removeprefix("Custom-")
    print(f"\nAll {len(batches)} batches accepted. HTTP 204 means accepted, not yet stored: "
          "allow a few minutes (longer for the first data in a new table), then check with:\n")
    print(f"  {table}\n  | summarize Events = count() by Result, bin(TimeGenerated, 1h)\n")


if __name__ == "__main__":
    main()
