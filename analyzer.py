import re
from collections import defaultdict

# How many failed logins before we flag an IP
FAILED_LOGIN_THRESHOLD = 5

# How many total requests before we flag an IP
REQUEST_SPAM_THRESHOLD = 100


def analyze_log(filepath):
    # These will count events per IP
    failed_logins = defaultdict(int)
    request_counts = defaultdict(int)

    with open(filepath, "r") as f:
        for line in f:

            # Count every line as a request for that IP
            ip = extract_ip(line)
            if ip:
                request_counts[ip] += 1

            # Check if this line is a failed login
            if is_failed_login(line):
                if ip:
                    failed_logins[ip] += 1

    # Build a list of suspicious findings
    alerts = []

    for ip, count in failed_logins.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "type": "Brute Force",
                "ip": ip,
                "detail": f"{count} failed login attempts"
            })

    for ip, count in request_counts.items():
        if count >= REQUEST_SPAM_THRESHOLD:
            alerts.append({
                "type": "Request Spam",
                "ip": ip,
                "detail": f"{count} requests detected"
            })

    return alerts


def extract_ip(line):
    # Grab the first IP address found in the line
    match = re.search(r'\b(\d{1,3}\.){3}\d{1,3}\b', line)
    return match.group() if match else None


def is_failed_login(line):
    # Look for common failed login keywords
    keywords = ["failed login", "authentication failure",
                 "invalid password", "invalid user"]
    line_lower = line.lower()
    return any(keyword in line_lower for keyword in keywords)
    