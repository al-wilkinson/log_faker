#!/usr/bin/env python3
"""
Generate synthetic sign-in events for a public-facing API integration host.

Produces a rolling window (default 24 hours, ending just before "now") of
baseline machine traffic, plus a hidden password-spray scenario, for ingestion
into a Microsoft Sentinel custom table via the Azure Monitor Logs Ingestion API.

Outputs (in --out-dir):
  events.json          full event set, a JSON array sorted by EventTime
  sample_events.json   small representative sample for the portal table wizard

Design notes:
  * Standard library only. No third-party packages needed.
  * All times are generated and written in UTC (ISO 8601, millisecond
    precision, 'Z' suffix). Business-hours logic uses Brisbane time
    (UTC+10, no daylight saving).
  * TimeGenerated can't be more than two days old when Azure receives it,
    so generate and send in the same session. The window is capped at 47 hours.
  * A fixed seed gives the same shape of data on every run (clients, patterns,
    scenario); only the absolute times move with the rolling window.
  * IP addresses come from the RFC 5737 documentation ranges, so none are real.
  * No passwords or secrets appear in any event.
"""

import argparse
import json
import os
import random
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
BRISBANE = timezone(timedelta(hours=10), "AEST")  # Queensland: UTC+10, no DST

# ---------------------------------------------------------------------------
# Traffic profile
# ---------------------------------------------------------------------------

# Relative activity by Brisbane hour (index 0-23) for "business hours" clients.
HOURLY_WEIGHTS = (
    [0.05] * 6            # 00:00-05:59 overnight
    + [0.2, 0.5, 0.9]     # 06:00-08:59 ramp up
    + [1.0] * 8           # 09:00-16:59 working day
    + [0.7, 0.4]          # 17:00-18:59 tail off
    + [0.2] * 4           # 19:00-22:59 evening
    + [0.1]               # 23:00-23:59
)
assert len(HOURLY_WEIGHTS) == 24

# Endpoint and HTTP method used by each authentication method.
ENDPOINTS = {
    "oauth_client_credentials": [("POST", "/oauth2/token")],
    "apikey": [("GET", "/v1/orders"), ("GET", "/v1/inventory"), ("POST", "/v1/shipments")],
    "mtls": [("POST", "/v1/telemetry"), ("GET", "/v1/config")],
    "basic": [("POST", "/v1/login")],
}

# Background failure reason by authentication method (normal noise, not attack).
NOISE_REASON = {
    "oauth_client_credentials": "ExpiredToken",
    "apikey": "InvalidSecret",
    "mtls": "InvalidCertificate",
    "basic": "InvalidCredentials",
}
NOISE_RATE_LIMITED = 0.004   # 0.4% of baseline events get a 429
NOISE_AUTH_FAILURE = 0.010   # 1.0% get an auth-method-specific 401

# Simulated integration clients. Patterns:
#   scheduled:  fixed interval with a little jitter (pollers, cron jobs)
#   business:   random arrivals following HOURLY_WEIGHTS (peak events per hour)
#   batch:      bursts at set Brisbane hours (nightly or midday syncs)
CLIENTS = [
    {"client_id": "partner-acme-01", "username": "svc_acme", "auth": "oauth_client_credentials",
     "ua": "python-requests/2.32.3", "ips": ["198.51.100.10"],
     "pattern": "scheduled", "interval_s": 300, "jitter_s": 8},
    {"client_id": "partner-globex-01", "username": "svc_globex", "auth": "oauth_client_credentials",
     "ua": "Java/17.0.9", "ips": ["198.51.100.21", "198.51.100.22"],
     "pattern": "scheduled", "interval_s": 900, "jitter_s": 20},
    {"client_id": "partner-initech-01", "username": "svc_initech", "auth": "apikey",
     "ua": "okhttp/4.12.0", "ips": ["198.51.100.34"],
     "pattern": "business", "peak_per_hour": 40},
    {"client_id": "partner-umbrella-01", "username": "svc_umbrella", "auth": "mtls",
     "ua": "Go-http-client/2.0", "ips": ["198.51.100.47"],
     "pattern": "business", "peak_per_hour": 25},
    {"client_id": "internal-reporting", "username": "svc_reporting", "auth": "oauth_client_credentials",
     "ua": "PowerShell/7.4.6", "ips": ["192.0.2.15"],
     "pattern": "batch", "local_hours": [2, 14], "burst_count": 150, "burst_minutes": 6},
    {"client_id": "partner-hooli-01", "username": "svc_hooli", "auth": "oauth_client_credentials",
     "ua": "axios/1.7.7", "ips": ["198.51.100.58"],
     "pattern": "scheduled", "interval_s": 300, "jitter_s": 5},
    {"client_id": "legacy-erp", "username": "svc_legacyerp", "auth": "basic",
     "ua": "Apache-HttpClient/4.5.14 (Java/1.8.0_402)", "ips": ["192.0.2.40"],
     "pattern": "scheduled", "interval_s": 600, "jitter_s": 15},
    {"client_id": "partner-stark-01", "username": "svc_stark", "auth": "apikey",
     "ua": "python-requests/2.31.0", "ips": ["198.51.100.70", "198.51.100.71"],
     "pattern": "business", "peak_per_hour": 50},
    {"client_id": "partner-wayne-01", "username": "svc_wayne", "auth": "oauth_client_credentials",
     "ua": "curl/8.5.0", "ips": ["198.51.100.83"],
     "pattern": "scheduled", "interval_s": 300, "jitter_s": 10},
    # Misconfigured on purpose: its secret was rotated and the client wasn't
    # updated, so it fails steadily from that point on. Noisy, but not an attack.
    {"client_id": "partner-oscorp-01", "username": "svc_oscorp", "auth": "oauth_client_credentials",
     "ua": "Microsoft.NET/8.0", "ips": ["198.51.100.95"],
     "pattern": "scheduled", "interval_s": 900, "jitter_s": 12,
     "secret_rotated_hours_ago": 6},
    {"client_id": "mobile-backend", "username": "svc_mobile", "auth": "oauth_client_credentials",
     "ua": "node-fetch/3.3.2", "ips": ["192.0.2.60", "192.0.2.61", "192.0.2.62"],
     "pattern": "business", "peak_per_hour": 30},
]

# ---------------------------------------------------------------------------
# Hidden scenario: password spray against the basic-auth login endpoint
# ---------------------------------------------------------------------------

ATTACKER_IPS = ["203.0.113.10", "203.0.113.23", "203.0.113.57", "203.0.113.88"]
ATTACKER_UA = "python-requests/2.28.1"   # close to legitimate clients on purpose
SPRAY_DURATION = timedelta(minutes=40)
SPRAY_PASSWORD_ROUNDS = 2                # passwords tried per username
SPRAY_TARGET = "svc_legacyerp"           # account that falls in round 2
FOLLOW_UP_LOGINS = 8                     # attacker's successful logins afterwards

# Usernames an attacker would guess, alongside the real client usernames.
GUESSED_USERNAMES = [
    "admin", "administrator", "api", "apiuser", "api_user", "test", "testuser", "guest",
    "root", "svc_api", "svc_backup", "svc_test", "svc_sync", "svc_admin", "integration",
    "integrations", "deploy", "jenkins", "monitor", "monitoring", "backup", "support",
    "dev", "devops", "sysadmin", "webapi", "service", "operator", "user", "demo", "sftp",
    "ftp", "oracle", "sql", "sa", "postgres", "mysql", "readonly", "reporting", "billing",
    "finance", "payroll", "sync", "etl", "scanner", "partner", "vendor", "erp", "crm",
    "sap", "middleware", "gateway", "proxy", "bot", "automation", "scheduler", "batch",
    "svc_erp", "svc_crm", "svc_partner",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def iso(t):
    """UTC ISO 8601 with millisecond precision and a 'Z' suffix."""
    t = t.astimezone(UTC)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def new_correlation_id(rng):
    """Random version 4 UUID drawn from the seeded generator (reproducible)."""
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def make_event(rng, t, client_id, username, ip, ua, auth, method, endpoint,
               result, reason, status):
    return {
        "EventTime": iso(t),
        "ClientId": client_id,
        "Username": username,
        "SourceIP": ip,
        "UserAgent": ua,
        "AuthMethod": auth,
        "Endpoint": endpoint,
        "HttpMethod": method,
        "Result": result,
        "FailureReason": reason,
        "HttpStatus": status,
        "CorrelationId": new_correlation_id(rng),
    }


def brisbane_days(start, end):
    """Brisbane calendar dates covering the window, with a day either side."""
    day = start.astimezone(BRISBANE).date() - timedelta(days=1)
    last = end.astimezone(BRISBANE).date() + timedelta(days=1)
    while day <= last:
        yield day
        day += timedelta(days=1)


def at_brisbane(day, hour, minute=0):
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=BRISBANE).astimezone(UTC)

# ---------------------------------------------------------------------------
# Arrival-time generators
# ---------------------------------------------------------------------------


def scheduled_times(rng, start, end, interval_s, jitter_s):
    """Fixed schedule with jitter around each slot (no cumulative drift)."""
    slot = start + timedelta(seconds=rng.uniform(0, interval_s))
    times = []
    while slot < end:
        t = slot + timedelta(seconds=rng.uniform(-jitter_s, jitter_s))
        if start <= t < end:
            times.append(t)
        slot += timedelta(seconds=interval_s)
    return times


def business_times(rng, start, end, peak_per_hour):
    """Random arrivals at the peak rate, thinned by the Brisbane hour weight."""
    rate_per_second = peak_per_hour / 3600.0
    times = []
    t = start
    while True:
        t += timedelta(seconds=rng.expovariate(rate_per_second))
        if t >= end:
            return times
        if rng.random() < HOURLY_WEIGHTS[t.astimezone(BRISBANE).hour]:
            times.append(t)


def batch_times(rng, start, end, local_hours, burst_count, burst_minutes):
    """Bursts starting within two minutes of each listed Brisbane hour."""
    times = []
    for day in brisbane_days(start, end):
        for hour in local_hours:
            burst_start = at_brisbane(day, hour) + timedelta(seconds=rng.uniform(0, 120))
            for _ in range(burst_count):
                t = burst_start + timedelta(seconds=rng.uniform(0, burst_minutes * 60))
                if start <= t < end:
                    times.append(t)
    return times

# ---------------------------------------------------------------------------
# Baseline traffic
# ---------------------------------------------------------------------------


def baseline_outcome(rng, auth):
    r = rng.random()
    if r < NOISE_RATE_LIMITED:
        return "Failure", "RateLimited", 429
    if r < NOISE_RATE_LIMITED + NOISE_AUTH_FAILURE:
        return "Failure", NOISE_REASON[auth], 401
    return "Success", None, 200


def generate_baseline(rng, start, end):
    events = []
    for c in CLIENTS:
        if c["pattern"] == "scheduled":
            times = scheduled_times(rng, start, end, c["interval_s"], c["jitter_s"])
        elif c["pattern"] == "business":
            times = business_times(rng, start, end, c["peak_per_hour"])
        elif c["pattern"] == "batch":
            times = batch_times(rng, start, end, c["local_hours"], c["burst_count"], c["burst_minutes"])
        else:
            raise ValueError(f"Unknown pattern: {c['pattern']}")

        rotated_at = None
        if "secret_rotated_hours_ago" in c:
            rotated_at = end - timedelta(hours=c["secret_rotated_hours_ago"])

        for t in times:
            method, endpoint = rng.choice(ENDPOINTS[c["auth"]])
            if rotated_at and t >= rotated_at:
                result, reason, status = "Failure", "InvalidSecret", 401
            else:
                result, reason, status = baseline_outcome(rng, c["auth"])
            events.append(make_event(
                rng, t, c["client_id"], c["username"], rng.choice(c["ips"]), c["ua"],
                c["auth"], method, endpoint, result, reason, status))
    return events

# ---------------------------------------------------------------------------
# Password spray scenario
# ---------------------------------------------------------------------------


def choose_spray_start(start, end):
    """Latest preferred overnight Brisbane time that fits inside the window.

    Needs at least one hour of baseline before it, and room after it for the
    spray plus the attacker's follow-up logins (75 minutes in total).
    """
    preferences = [(1, 30), (2, 30), (0, 30), (3, 30), (23, 30), (4, 0)]
    for hour, minute in preferences:
        best = None
        for day in brisbane_days(start, end):
            candidate = at_brisbane(day, hour, minute)
            if (candidate >= start + timedelta(hours=1)
                    and candidate + timedelta(minutes=75) <= end):
                best = candidate   # keep the latest one that fits
        if best:
            return best
    return start + (end - start) / 2   # fallback for very short windows


def generate_spray(rng, start, end):
    known = {c["username"]: c["client_id"] for c in CLIENTS}

    users = GUESSED_USERNAMES + list(known)
    rng.shuffle(users)
    # Put the target 60% of the way through the list so it falls late in round 2.
    users.remove(SPRAY_TARGET)
    users.insert(int(len(users) * 0.6), SPRAY_TARGET)

    attempts = [(rnd, u) for rnd in range(SPRAY_PASSWORD_ROUNDS) for u in users]
    spray_start = choose_spray_start(start, end)
    interval = SPRAY_DURATION / len(attempts)

    events = []
    compromised_at = None
    compromised_ip = None
    for i, (rnd, user) in enumerate(attempts):
        if compromised_at and user == SPRAY_TARGET:
            continue   # already has this password; no need to try again
        t = spray_start + i * interval + timedelta(seconds=rng.uniform(-0.3, 0.3))
        ip = ATTACKER_IPS[i % len(ATTACKER_IPS)]
        client_id = known.get(user)
        if user == SPRAY_TARGET and rnd == SPRAY_PASSWORD_ROUNDS - 1:
            result, reason, status = "Success", None, 200
            compromised_at, compromised_ip = t, ip
        elif client_id:
            result, reason, status = "Failure", "InvalidCredentials", 401
        else:
            result, reason, status = "Failure", "UnknownUser", 401
        events.append(make_event(
            rng, t, client_id, user, ip, ATTACKER_UA, "basic", "POST", "/v1/login",
            result, reason, status))

    # The attacker comes back with the stolen credentials from the same IP.
    t = compromised_at + timedelta(minutes=3)
    for _ in range(FOLLOW_UP_LOGINS):
        t += timedelta(seconds=rng.uniform(90, 210))
        events.append(make_event(
            rng, t, known[SPRAY_TARGET], SPRAY_TARGET, compromised_ip, ATTACKER_UA,
            "basic", "POST", "/v1/login", "Success", None, 200))

    scenario = {
        "spray_start": spray_start,
        "spray_end": spray_start + SPRAY_DURATION,
        "attempts": len(events) - FOLLOW_UP_LOGINS,
        "usernames": len(users),
        "compromised_user": SPRAY_TARGET,
        "compromised_at": compromised_at,
        "compromised_ip": compromised_ip,
        "follow_up_end": t,
    }
    return events, scenario

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def build_sample(events, size=15):
    """A small mixed sample: the first event per client, plus one per failure reason.

    Every field has a non-null value somewhere, so the portal wizard can infer
    a column type for each one.
    """
    sample, seen_clients, seen_reasons = [], set(), set()
    for e in events:
        if e["Result"] == "Success" and e["ClientId"] not in seen_clients:
            sample.append(e)
            seen_clients.add(e["ClientId"])
        elif e["FailureReason"] and e["FailureReason"] not in seen_reasons:
            sample.append(e)
            seen_reasons.add(e["FailureReason"])
        if len(sample) >= size:
            break
    return sorted(sample, key=lambda e: e["EventTime"])


def both_times(t):
    return f"{iso(t)} UTC  |  {t.astimezone(BRISBANE):%Y-%m-%d %H:%M:%S} Brisbane"


def print_summary(events, scenario, start, end, out_dir):
    print(f"Window:  {both_times(start)}")
    print(f"     to  {both_times(end)}")
    print(f"Events:  {len(events)} written to {os.path.join(out_dir, 'events.json')}")
    print()

    print("Events per client (ClientId empty = unknown username):")
    per_client = Counter(e["ClientId"] or "(none)" for e in events)
    for client, count in per_client.most_common():
        print(f"  {client:<22} {count:>6}")
    print()

    print("Results:")
    for (result, reason), count in Counter(
            (e["Result"], e["FailureReason"] or "-") for e in events).most_common():
        print(f"  {result:<8} {reason:<20} {count:>6}")
    print()

    s = scenario
    print("Hidden scenario: password spray against POST /v1/login (basic auth)")
    print(f"  Spray window:    {both_times(s['spray_start'])}")
    print(f"               to  {both_times(s['spray_end'])}")
    print(f"  Attempts:        {s['attempts']} across {s['usernames']} usernames "
          f"from {', '.join(ATTACKER_IPS)}")
    print(f"  Compromised:     {s['compromised_user']} from {s['compromised_ip']}")
    print(f"                   at {both_times(s['compromised_at'])}")
    print(f"  Follow-up:       {FOLLOW_UP_LOGINS} successful logins until "
          f"{both_times(s['follow_up_end'])}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--seed", type=int, default=42,
                        help="random seed; same seed gives the same shape of data (default 42)")
    parser.add_argument("--hours", type=float, default=24,
                        help="window length in hours, ending now (default 24, max 47)")
    parser.add_argument("--out-dir", default=".", help="where to write the JSON files")
    args = parser.parse_args()

    if not 3 <= args.hours <= 47:
        parser.error("--hours must be between 3 and 47 (TimeGenerated must be under two days old)")

    rng = random.Random(args.seed)
    end = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=2)
    start = end - timedelta(hours=args.hours)

    events = generate_baseline(rng, start, end)
    spray_events, scenario = generate_spray(rng, start, end)
    events.extend(spray_events)
    events.sort(key=lambda e: e["EventTime"])

    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "events.json"), "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)
    with open(os.path.join(args.out_dir, "sample_events.json"), "w", encoding="utf-8") as f:
        json.dump(build_sample(events), f, indent=2)

    print_summary(events, scenario, start, end, args.out_dir)


if __name__ == "__main__":
    main()
