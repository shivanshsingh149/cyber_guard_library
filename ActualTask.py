
import re
import ipaddress
from urllib.parse import urlsplit


# ==========================================
# CONSTANTS
# ==========================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "account",
    "password",
    "banking",
    "secure",
    "signin",
    "confirm",
    "free"
]

SHORTENED_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd"
]


# ==========================================
# 1. validate_url()
# Validates the entered website URL
# ==========================================

def validate_url(url):

    if not isinstance(url, str):
        raise ValueError("URL must be entered as text.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if " " in url:
        raise ValueError("URL must not contain spaces.")

    try:
        parsed = urlsplit(url)

        if parsed.scheme not in ["http", "https"]:
            raise ValueError(
                "URL must start with http:// or https://"
            )

        if not parsed.hostname:
            raise ValueError(
                "Invalid URL: hostname is missing."
            )

        # Validate the port number
        _ = parsed.port

    except ValueError as error:
        raise ValueError(f"Invalid URL: {error}")

    return True


# ==========================================
# 2. check_ip_address()
# Checks whether hostname is an IP address
# ==========================================

def check_ip_address(hostname):

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


# ==========================================
# 3. analyze_url()
# Checks suspicious characteristics of URL
# ==========================================

def analyze_url(url):

    validate_url(url)

    parsed = urlsplit(url)
    hostname = parsed.hostname.lower()

    checks = {
        "ip_address": False,
        "no_https": False,
        "suspicious_keywords": False,
        "shortened_url": False,
        "at_symbol": False,
        "unusual_structure": False
    }

    warnings = []

    # Check 1: IP address instead of domain
    if check_ip_address(hostname):

        checks["ip_address"] = True

        warnings.append(
            "Website uses an IP address instead of a domain name."
        )

    # Check 2: Website does not use HTTPS
    if parsed.scheme == "http":

        checks["no_https"] = True

        warnings.append(
            "Website does not use HTTPS."
        )

    # Check 3: Suspicious keywords
    url_lower = url.lower()

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:

            checks["suspicious_keywords"] = True

            warnings.append(
                f"Suspicious keyword detected: {keyword}"
            )

            break

    # Check 4: URL shortening service
    if hostname in SHORTENED_DOMAINS:

        checks["shortened_url"] = True

        warnings.append(
            "URL uses a known shortening service."
        )

    # Check 5: @ symbol in URL
    if "@" in parsed.netloc:

        checks["at_symbol"] = True

        warnings.append(
            "URL contains an @ symbol."
        )

    # Check 6: Unusual domain structure
    if (
        len(hostname) > 50
        or len(hostname.split(".")) > 4
        or "xn--" in hostname
    ):

        checks["unusual_structure"] = True

        warnings.append(
            "URL has an unusual domain structure."
        )

    return {
        "url": url,
        "hostname": hostname,
        "checks": checks,
        "warnings": warnings
    }


# ==========================================
# 4. calculate_url_risk()
# Calculates risk score out of 100
# ==========================================

def calculate_url_risk(checks):

    risk_points = {
        "ip_address": 25,
        "no_https": 10,
        "suspicious_keywords": 15,
        "shortened_url": 15,
        "at_symbol": 20,
        "unusual_structure": 15
    }

    score = 0

    for check, points in risk_points.items():

        if checks.get(check, False):

            score += points

    # Determine risk category
    if score < 30:

        category = "LOW"

    elif score < 60:

        category = "MEDIUM"

    else:

        category = "HIGH"

    return {
        "score": score,
        "category": category
    }


# ==========================================
# 5. detect_phishing()
# Main phishing detection function
# ==========================================

def detect_phishing(url):

    # Analyze the URL
    analysis = analyze_url(url)

    # Calculate risk score
    risk = calculate_url_risk(
        analysis["checks"]
    )

    # Store final result
    result = {
        "url": analysis["url"],
        "hostname": analysis["hostname"],
        "score": risk["score"],
        "category": risk["category"],
        "warnings": analysis["warnings"]
    }

    # Give recommendation
    if risk["category"] == "LOW":

        result["recommendation"] = (
            "No major warning signs detected. "
            "Still verify the website before sharing personal information."
        )

    elif risk["category"] == "MEDIUM":

        result["recommendation"] = (
            "Be careful. Verify the website address before proceeding."
        )

    else:

        result["recommendation"] = (
            "High-risk URL detected. Avoid entering passwords "
            "or personal information on this website."
        )

    return result


# ==========================================
# 6. format_report()
# Displays final phishing detection report
# ==========================================

def format_report(result):

    report = []

    report.append("\n========== CYBERGUARD REPORT ==========")

    report.append(
        f"Website URL : {result['url']}"
    )

    report.append(
        f"Domain      : {result['hostname']}"
    )

    report.append("---------------------------------------")

    report.append(
        f"Risk Score  : {result['score']}/100"
    )

    report.append(
        f"Risk Level  : {result['category']}"
    )

    report.append("---------------------------------------")

    report.append("SECURITY WARNINGS:")

    if result["warnings"]:

        for warning in result["warnings"]:

            report.append(f"- {warning}")

    else:

        report.append(
            "- No suspicious indicators detected."
        )

    report.append("---------------------------------------")

    report.append("RECOMMENDATION:")

    report.append(
        result["recommendation"]
    )

    report.append("=======================================")

    return "\n".join(report)
