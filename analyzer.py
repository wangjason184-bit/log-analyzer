import re
from collections import defaultdict
from datetime import datetime

# ── Thresholds ────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW    = 60     # seconds
RATE_SPIKE_THRESHOLD  = 50
RATE_SPIKE_WINDOW     = 10     # seconds
MAX_EVIDENCE_LINES    = 5      # how many raw lines to show per alert

# ── Patterns ──────────────────────────────────────────────────
NGINX_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]'
    r'\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})'
)

TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
FAILED_STATUS_CODES  = {"401", "403"}
SUCCESS_STATUS_CODES = {"200", "302"}
LOGIN_PATHS = ["/login", "/admin", "/wp-login.php",
               "/signin", "/auth", "/account"]


def parse_timestamp(raw):
    try:
        return datetime.strptime(raw, TIMESTAMP_FORMAT)
    except ValueError:
        return None


def parse_line(line):
    match = NGINX_PATTERN.search(line)
    if not match:
        return None
    data = match.groupdict()
    data["timestamp"] = parse_timestamp(data["timestamp"])
    data["raw"] = line.strip()  # ← store the original line
    return data


def detect_brute_force(events):
    """
    events: dict of ip -> list of (timestamp, status, path, raw_line)
    Returns alerts with evidence lines attached.
    """
    alerts = []

    for ip, ip_events in events.items():
        timed = [(ts, st, path, raw)
                 for ts, st, path, raw in ip_events if ts]
        timed.sort(key=lambda x: x[0])

        failure_window = []  # list of (timestamp, raw_line)

        for ts, status, path, raw in timed:
            is_login_path = any(p in path for p in LOGIN_PATHS)
            if not is_login_path:
                continue

            # Success resets the window
            if status in SUCCESS_STATUS_CODES:
                failure_window = []
                continue

            if status in FAILED_STATUS_CODES:
                failure_window.append((ts, raw))

                # Drop events outside the time window
                failure_window = [
                    (t, r) for t, r in failure_window
                    if (ts - t).total_seconds() <= BRUTE_FORCE_WINDOW
                ]

                if len(failure_window) >= BRUTE_FORCE_THRESHOLD:
                    # Grab up to MAX_EVIDENCE_LINES raw lines
                    evidence = [r for _, r in
                                failure_window[:MAX_EVIDENCE_LINES]]
                    alerts.append({
                        "type": "Brute Force Attack",
                        "ip": ip,
                        "severity": "high",
                        "count": len(failure_window),
                        "window_seconds": BRUTE_FORCE_WINDOW,
                        "detail": (
                            f"This IP made {len(failure_window)} failed "
                            f"login attempts within {BRUTE_FORCE_WINDOW} "
                            f"seconds. Logins reset on success so these "
                            f"are genuine repeated failures."
                        ),
                        "action": "Block this IP immediately.",
                        "evidence": evidence  # ← real log lines
                    })
                    break

    return alerts


def detect_rate_spike(events):
    """
    events: dict of ip -> list of (timestamp, raw_line)
    """
    alerts = []

    for ip, ip_events in events.items():
        timed = sorted(
            [(t, r) for t, r in ip_events if t],
            key=lambda x: x[0]
        )

        window = []  # list of (timestamp, raw_line)
        peak_window = []

        for ts, raw in timed:
            window.append((ts, raw))

            window = [
                (t, r) for t, r in window
                if (ts - t).total_seconds() <= RATE_SPIKE_WINDOW
            ]

            if len(window) > len(peak_window):
                peak_window = list(window)

            if len(window) >= RATE_SPIKE_THRESHOLD:
                evidence = [r for _, r in
                            peak_window[:MAX_EVIDENCE_LINES]]
                alerts.append({
                    "type": "Request Rate Spike",
                    "ip": ip,
                    "severity": "medium",
                    "count": len(peak_window),
                    "window_seconds": RATE_SPIKE_WINDOW,
                    "detail": (
                        f"This IP sent {len(peak_window)} requests in "
                        f"under {RATE_SPIKE_WINDOW} seconds. Normal "
                        f"browsers don't do this — looks like automated "
                        f"scanning or denial-of-service."
                    ),
                    "action": "Consider rate limiting or blocking this IP.",
                    "evidence": evidence  # ← real log lines
                })
                break

    return alerts


def analyze_log(filepath):
    login_events   = defaultdict(list)
    request_events = defaultdict(list)

    total_lines    = 0
    unparsed_lines = 0

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            total_lines += 1
            parsed = parse_line(line)

            if parsed:
                ip     = parsed["ip"]
                ts     = parsed["timestamp"]
                status = parsed["status"]
                path   = parsed["path"].lower()
                raw    = parsed["raw"]

                login_events[ip].append((ts, status, path, raw))
                request_events[ip].append((ts, raw))
            else:
                unparsed_lines += 1
                ip = _extract_ip(line)
                if ip and _is_failed_login(line):
                    login_events[ip].append((None, "401", "/login", line.strip()))

    alerts = []
    alerts += detect_brute_force(login_events)
    alerts += detect_rate_spike(request_events)

    meta = {
        "total_lines": total_lines,
        "unparsed_lines": unparsed_lines,
    }

    return alerts, meta


def _extract_ip(line):
    match = re.search(r'\b(\d{1,3}\.){3}\d{1,3}\b', line)
    return match.group() if match else None


def _is_failed_login(line):
    keywords = ["failed login", "authentication failure",
                 "invalid password", "invalid user"]
    return any(kw in line.lower() for kw in keywords)
