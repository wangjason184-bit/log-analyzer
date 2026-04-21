import re
from collections import defaultdict

FAILED_LOGIN_THRESHOLD = 5
REQUEST_SPAM_THRESHOLD = 100

NGINX_APACHE_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'[^"]*"'
    r'(?P<method>\w+)\s'
    r'(?P<path>\S+)\s'
    r'HTTP/[\d.]+"\s'
    r'(?P<status>\d{3})'
)

FAILED_STATUS_CODES = {"401", "403"}
LOGIN_PATHS = ["/login", "/admin", "/wp-login.php",
               "/signin", "/auth", "/account"]


def analyze_log(filepath):
    failed_logins = defaultdict(int)
    request_counts = defaultdict(int)

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            result = parse_nginx_apache(line)

            if result:
                ip = result["ip"]
                status = result["status"]
                path = result["path"].lower()

                request_counts[ip] += 1

                if status in FAILED_STATUS_CODES and any(p in path for p in LOGIN_PATHS):
                    failed_logins[ip] += 1

            else:
                ip = extract_ip(line)
                if ip:
                    request_counts[ip] += 1
                    if is_failed_login(line):
                        failed_logins[ip] += 1

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


def parse_nginx_apache(line):
    match = NGINX_APACHE_PATTERN.search(line)
    if match:
        return match.groupdict()
    return None


def extract_ip(line):
    match = re.search(r'\b(\d{1,3}\.){3}\d{1,3}\b', line)
    return match.group() if match else None


def is_failed_login(line):
    keywords = ["failed login", "authentication failure",
                 "invalid password", "invalid user"]
    line_lower = line.lower()
    return any(keyword in line_lower for keyword in keywords)
