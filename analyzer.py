import re
from collections import defaultdict
from datetime import datetime

# ── Thresholds ────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5      # failed logins within the window
BRUTE_FORCE_WINDOW    = 60     # seconds - 5 failures in 60s = attack
RATE_SPIKE_THRESHOLD  = 50     # requests within the window
RATE_SPIKE_WINDOW     = 10     # seconds - 50 requests in 10s = spike

# ── Patterns ──────────────────────────────────────────────────
NGINX_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]'
    r'\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})'
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

FAILED_STATUS_CODES = {"401", "403"}
LOGIN_PATHS = ["/login", "/admin", "/wp-login.php",
               "/signin", "/auth", "/account"]
SUCCESS_STATUS_CODES = {"200", "302"}


def parse_timestamp(raw):
    """Convert log timestamp string to a Python datetime object."""
    try:
        return datetime.strptime(raw, TIMESTAMP_FORMAT)
    except ValueError:
        return None


def parse_line(line):
    """
    Try to parse a log line as nginx/Apache format.
    Returns a dict with ip, timestamp, method, path, status
    or None if the line doesn't match.
    """
    match = NGINX_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()
    data["timestamp"] = parse_timestamp(data["timestamp"])
    return data


def detect_brute_force(events):
    """
    events: list of (timestamp, status, path) per IP

    Logic:
    - Walk through events in time order
    - Count consecutive failures on login paths
    - Reset counter if a SUCCESS is seen on a login path
    - Flag if BRUTE_FORCE_THRESHOLD failures occur
      within BRUTE_FORCE_WINDOW seconds
    """
    alerts = []

    for ip, ip_events in events.items():
        # Sort by timestamp, skip events with no timestamp
        timed = [(ts, st, path) for ts, st, path in ip_events if ts]
        timed.sort(key=lambda x: x[0])

        # Sliding window of failure timestamps
        failure_times = []

        for ts, status, path in timed:
            is_login_path = any(p in path for p in LOGIN_PATHS)

            if not is_login_path:
                continue

            # Success on a login page → reset the failure window
            if status in SUCCESS_STATUS_CODES:
                failure_times = []
                continue

            # Failed login attempt
            if status in FAILED_STATUS_CODES:
                failure_times.append(ts)

                # Drop failures outside the time window
                failure_times = [
                    t for t in failure_times
                    if (ts - t).total_seconds() <= BRUTE_FORCE_WINDOW
                ]

                # Check if threshold is hit
                if len(failure_times) >= BRUTE_FORCE_THRESHOLD:
                    alerts.append({
                        "type": "Brute Force Attack",
                        "ip": ip,
                        "severity": "high",
                        "count": len(failure_times),
                        "window_seconds": BRUTE_FORCE_WINDOW,
                        "detail": (
                            f"This IP made {len(failure_times)} failed login "
                            f"attempts within {BRUTE_FORCE_WINDOW} seconds. "
                            f"Logins reset on success so these are genuine "
                            f"repeated failures — classic brute force pattern."
                        ),
                        "action": "Block this IP immediately."
                    })
                    break  # one alert per IP is enough

    return alerts


def detect_rate_spike(events):
    """
    events: list of (timestamp,) per IP

    Logic:
    - Sliding window over all requests (not just login paths)
    - If any window of RATE_SPIKE_WINDOW seconds contains
      >= RATE_SPIKE_THRESHOLD requests → flag it
    """
    alerts = []

    for ip, timestamps in events.items():
        timed = sorted([t for t in timestamps if t])

        window = []
        peak = 0

        for ts in timed:
            window.append(ts)

            # Drop requests outside the window
            window = [
                t for t in window
                if (ts - t).total_seconds() <= RATE_SPIKE_WINDOW
            ]

            peak = max(peak, len(window))

            if len(window) >= RATE_SPIKE_THRESHOLD:
                alerts.append({
                    "type": "Request Rate Spike",
                    "ip": ip,
                    "severity": "medium",
                    "count": peak,
                    "window_seconds": RATE_SPIKE_WINDOW,
                    "detail": (
                        f"This IP sent {peak} requests in under "
                        f"{RATE_SPIKE_WINDOW} seconds. Normal browsers "
                        f"don't do this — it looks like automated "
                        f"scanning or a denial-of-service attempt."
                    ),
                    "action": "Consider rate limiting or blocking this IP."
                })
                break  # one alert per IP

    return alerts


def analyze_log(filepath):
    """
    Main entry point.
    Reads a log file, parses each line, runs detectors,
    returns a list of alert dicts.
    """
    # Per-IP event log: (timestamp, status, path)
    login_events   = defaultdict(list)  # for brute force
    request_events = defaultdict(list)  # for rate spike

    unparsed_lines     = 0
    total_lines        = 0
    no_timestamp_lines = 0

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            total_lines += 1
            parsed = parse_line(line)

            if parsed:
                ip        = parsed["ip"]
                ts        = parsed["timestamp"]
                status    = parsed["status"]
                path      = parsed["path"].lower()

                if ts is None:
                    no_timestamp_lines += 1

                login_events[ip].append((ts, status, path))
                request_events[ip].append(ts)

            else:
                unparsed_lines += 1
                # Fallback: plain text log (no timestamp → weaker detection)
                ip = _extract_ip(line)
                if ip and _is_failed_login(line):
                    login_events[ip].append((None, "401", "/login"))

    alerts = []
    alerts += detect_brute_force(login_events)
    alerts += detect_rate_spike(request_events)

    # Attach metadata so the frontend can show scan stats
    meta = {
        "total_lines": total_lines,
        "unparsed_lines": unparsed_lines,
        "no_timestamp_lines": no_timestamp_lines,
    }

    return alerts, meta


# ── Fallback helpers for plain-text logs ──────────────────────

def _extract_ip(line):
    match = re.search(r'\b(\d{1,3}\.){3}\d{1,3}\b', line)
    return match.group() if match else None


def _is_failed_login(line):
    keywords = ["failed login", "authentication failure",
                 "invalid password", "invalid user"]
    return any(kw in line.lower() for kw in keywords)
