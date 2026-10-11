"""
PhishGuard - Complete URL Feature Extractor & Analysis Module
College CSE Mini Project: Phishing Website Detection System

This module performs lexical, structural, and semantic feature extraction from URLs.
Calculates categorical characteristics, rule-based indicators, and numerical feature vectors.
"""

import re
from urllib.parse import urlparse

# Suspicious keywords frequently used in phishing attacks (as specified in Section 6)
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "account", "secure",
    "update", "password", "banking", "wallet", "confirm",
    "authentication", "free", "gift", "bonus", "urgent"
]

# Misleading brand terms frequently impersonated in phishing lures
POPULAR_BRANDS = [
    "paypal", "apple", "google", "netflix", "amazon", "microsoft",
    "facebook", "instagram", "chase", "wellsfargo", "binance",
    "coinbase", "dropbox", "steam", "twitter", "spotify"
]

# Common URL shortening services
SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorturl.at"
}

# TLDs historically associated with high phishing and spam activity
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "cc", "club",
    "vip", "work", "biz", "site", "online"
}

# Regular expression to test for IPv4 addresses in hostname
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
IPV6_REGEX = re.compile(r"^\[?[0-9a-fA-F:]+\]?$")


def is_private_ip_host(hostname: str) -> bool:
    """Checks whether the hostname is a private/local IP address (RFC 1918, loopback, link-local)."""
    if not hostname:
        return False
    h = hostname.lower().strip("[]")
    if h == "localhost" or h == "::1":
        return True
    if IPV4_REGEX.match(h):
        try:
            parts = [int(p) for p in h.split(".")]
            if parts[0] == 10:  # 10.0.0.0/8
                return True
            if parts[0] == 127:  # 127.0.0.0/8
                return True
            if parts[0] == 192 and parts[1] == 168:  # 192.168.0.0/16
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:  # 172.16.0.0/12
                return True
            if parts[0] == 169 and parts[1] == 254:  # 169.254.0.0/16
                return True
        except (ValueError, IndexError):
            return False
    elif ":" in h:
        if h.startswith("fe80:") or h.startswith("fc") or h.startswith("fd"):
            return True
    return False


def validate_and_normalize_url(raw_url: str):
    """
    Validates user input against length, protocol, and hostname constraints.
    Returns (normalized_url, error_message).
    """
    if raw_url is None:
        return None, "Please enter a valid website URL."

    url = raw_url.strip()
    if not url:
        return None, "Please enter a valid website URL."

    if len(url) > 2048:
        return None, "URL is too long. Maximum allowed length is 2048 characters."

    # Check for unsupported schemes
    lower = url.lower()
    unsupported_schemes = ("ftp://", "file://", "javascript:", "data:", "mailto:", "ws://", "wss://")
    for s in unsupported_schemes:
        if lower.startswith(s):
            return None, f"Unsupported protocol '{s}'. PhishGuard analyzes HTTP and HTTPS URLs only."

    # Normalize default scheme if omitted
    has_scheme = lower.startswith("http://") or lower.startswith("https://")
    if not has_scheme:
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception as e:
        return None, f"Malformed URL: {str(e)}"

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        return None, "Invalid URL: Hostname is missing."

    # Minimum domain or IP check
    is_ip = bool(IPV4_REGEX.match(hostname)) or bool(IPV6_REGEX.match(hostname) and ":" in hostname)
    if not is_ip and "." not in hostname and hostname != "localhost":
        return None, "Invalid URL: Domain must contain at least one top-level domain dot (e.g. example.com)."

    return url, None


def extract_features(raw_url: str) -> dict:
    """
    Extracts 20 lexical, structural, and semantic features plus
    human-readable categorical characteristics from the URL.
    """
    normalized_url, err = validate_and_normalize_url(raw_url)
    if err:
        raise ValueError(err)

    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    url_lower = normalized_url.lower()

    # 1. URL length & categorical rating
    url_len = len(normalized_url)
    if url_len < 54:
        url_length_cat = "Normal"
    elif url_len <= 75:
        url_length_cat = "Long"
    else:
        url_length_cat = "Very Long"

    # 2. Domain length & categorical rating
    domain_len = len(hostname)
    domain_length_cat = "Normal" if domain_len <= 24 else "Long"

    # 3. Dots & Hyphens & Digits
    num_dots = normalized_url.count(".")
    num_hyphens = normalized_url.count("-")
    num_digits = sum(1 for c in normalized_url if c.isdigit())

    parts = hostname.split(".")
    # If hostname is an IP address, subdomains are 0
    is_ip = 1 if (IPV4_REGEX.match(hostname) or (":" in hostname and IPV6_REGEX.match(hostname))) else 0
    is_private_ip = 1 if (is_ip and is_private_ip_host(hostname)) else 0
    if is_ip:
        num_subdomains = 0
        subdomain_structure = "Normal"
    else:
        # Standard example.com has 2 parts -> 0 subdomains
        # www.example.com has 3 parts -> 1 subdomain
        num_subdomains = max(0, len(parts) - 2) if len(parts) >= 2 else 0
        subdomain_structure = "Normal" if num_subdomains <= 1 else "Unusual"

    # 5. Special characters
    special_chars = set("!*;'():@&=+$,/?#[]~_-")
    num_special_chars = sum(1 for c in normalized_url if c in special_chars)
    if num_special_chars <= 5:
        special_chars_cat = "Low"
    elif num_special_chars <= 10:
        special_chars_cat = "Medium"
    else:
        special_chars_cat = "High"

    # 6. Presence of '@'
    has_at_symbol = 1 if "@" in normalized_url else 0

    # 7. URL Shortening
    matched_shortener = next((svc for svc in SHORTENING_SERVICES if svc in hostname), None)
    is_shortened = 1 if matched_shortener else 0

    # 8. Unusual Port
    port = parsed.port
    has_unusual_port = 1 if port and port not in (80, 443) else 0

    # 9. HTTPS
    has_https = 1 if parsed.scheme == "https" else 0

    # 10. Delimiters
    num_slash = normalized_url.count("/")
    num_question = normalized_url.count("?")
    num_equal = normalized_url.count("=")
    num_percent = normalized_url.count("%")

    # 11. Suspicious keywords
    matched_keywords = [w for w in SUSPICIOUS_KEYWORDS if w in url_lower]
    suspicious_keyword_count = len(matched_keywords)

    # 12. TLD & Domain depth
    tld = parts[-1] if len(parts) > 1 and not is_ip else ""
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    domain_depth = len(parts) + (1 if is_suspicious_tld else 0)

    # 13. Excessive subdomains
    excessive_subdomains = 1 if num_subdomains > 2 else 0

    # 14. Brand spoofing
    matched_brands = []
    for brand in POPULAR_BRANDS:
        if brand in url_lower:
            legit_pattern = rf"(^|\.){re.escape(brand)}\.[a-z]{{2,4}}$"
            if not re.search(legit_pattern, hostname):
                matched_brands.append(brand)
    misleading_brand_count = len(matched_brands)

    features = {
        "url_length": url_len,
        "domain_length": domain_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_subdomains": num_subdomains,
        "num_special_chars": num_special_chars,
        "num_digits": num_digits,
        "has_at_symbol": has_at_symbol,
        "is_ip_address": is_ip,
        "is_shortened": is_shortened,
        "has_unusual_port": has_unusual_port,
        "has_https": has_https,
        "num_slash": num_slash,
        "num_question": num_question,
        "num_equal": num_equal,
        "num_percent": num_percent,
        "suspicious_keyword_count": suspicious_keyword_count,
        "domain_depth": domain_depth,
        "excessive_subdomains": excessive_subdomains,
        "misleading_brand_count": misleading_brand_count,
    }

    # Structured 15-characteristic table requested in Section 1 and Section 4
    characteristics_table = [
        {
            "feature": "URL Length",
            "actualResult": f"{url_length_cat} ({url_len} chars)",
            "category": "normal" if url_length_cat == "Normal" else ("warning" if url_length_cat == "Long" else "danger"),
            "detail": "<54 chars is standard"
        },
        {
            "feature": "HTTPS",
            "actualResult": "Enabled" if has_https else "Not Enabled",
            "category": "normal" if has_https else "warning",
            "detail": "Encrypted SSL connection" if has_https else "Plaintext HTTP connection"
        },
        {
            "feature": "IP Address",
            "actualResult": f"Detected (Private IP: {hostname})" if (is_ip and is_private_ip) else ("Detected (Public IP)" if is_ip else "Not Detected"),
            "category": "normal" if (not is_ip or is_private_ip) else "warning",
            "detail": f"Local network / RFC 1918 address ({hostname}). Not proof of phishing." if (is_ip and is_private_ip) else (f"Host is direct public IP ({hostname})" if is_ip else "Standard named domain")
        },
        {
            "feature": "Domain Length",
            "actualResult": f"{domain_length_cat} ({domain_len} chars)",
            "category": "normal" if domain_length_cat == "Normal" else "warning",
            "detail": "Normal domain range is 8-24 chars"
        },
        {
            "feature": "Number of Subdomains",
            "actualResult": str(num_subdomains),
            "category": "danger" if num_subdomains > 2 else ("warning" if num_subdomains > 1 else "normal"),
            "detail": f"{num_subdomains} subdomain level(s)"
        },
        {
            "feature": "Subdomain Structure",
            "actualResult": subdomain_structure,
            "category": "danger" if subdomain_structure == "Unusual" else "normal",
            "detail": "Multiple nested subdomains often mask true domain" if subdomain_structure == "Unusual" else "Standard domain depth"
        },
        {
            "feature": "Suspicious Keywords",
            "actualResult": ", ".join(matched_keywords) if matched_keywords else "None",
            "category": "danger" if len(matched_keywords) >= 2 else ("warning" if matched_keywords else "normal"),
            "detail": f"{len(matched_keywords)} keyword(s) matched" if matched_keywords else "No lure keywords detected"
        },
        {
            "feature": "Special Characters",
            "actualResult": f"{special_chars_cat} ({num_special_chars} symbols)",
            "category": "danger" if special_chars_cat == "High" else ("warning" if special_chars_cat == "Medium" else "normal"),
            "detail": "Counts delimiters & symbols"
        },
        {
            "feature": "Number of Dots",
            "actualResult": str(num_dots),
            "category": "warning" if num_dots >= 4 else "normal",
            "detail": "Total dot separators"
        },
        {
            "feature": "Number of Hyphens",
            "actualResult": str(num_hyphens),
            "category": "danger" if num_hyphens >= 3 else ("warning" if num_hyphens > 1 else "normal"),
            "detail": "Hyphens frequently appear in typosquatting"
        },
        {
            "feature": "Number of Digits",
            "actualResult": str(num_digits),
            "category": "warning" if num_digits >= 6 else "normal",
            "detail": "Digits in URL structure"
        },
        {
            "feature": "Presence of @ Symbol",
            "actualResult": "Detected" if has_at_symbol else "Not Detected",
            "category": "danger" if has_at_symbol else "normal",
            "detail": "Used to mislead browser address parsing" if has_at_symbol else "No redirection symbol"
        },
        {
            "feature": "URL Shortener",
            "actualResult": f"Detected ({matched_shortener})" if is_shortened else "Not Detected",
            "category": "danger" if is_shortened else "normal",
            "detail": "Hides real target destination" if is_shortened else "Direct domain address"
        },
        {
            "feature": "Unusual Port",
            "actualResult": f"Detected (Port {port})" if has_unusual_port else "Not Detected",
            "category": "warning" if has_unusual_port else "normal",
            "detail": "Non-standard web communication port" if has_unusual_port else "Standard web port"
        },
        {
            "feature": "URL Format",
            "actualResult": "Valid",
            "category": "normal",
            "detail": f"Protocol: {parsed.scheme} | Host: {hostname}"
        }
    ]

    return {
        "features": features,
        "characteristics_table": characteristics_table,
        "meta": {
            "normalized_url": normalized_url,
            "hostname": hostname,
            "scheme": parsed.scheme,
            "is_private_ip": bool(is_private_ip),
            "matched_keywords": matched_keywords,
            "matched_brands": matched_brands,
            "tld": tld,
            "port": port,
            "matched_shortener": matched_shortener,
        }
    }


def generate_indicators_and_recs(features_dict: dict, meta: dict):
    """
    Generates explainable positive indicators, potential warning indicators,
    and tailored security recommendations based strictly on findings.
    """
    warnings = []
    positives = []
    recommendations = []

    # 1. Host indicators
    if features_dict["is_ip_address"]:
        if meta.get("is_private_ip", False):
            positives.append(f"Private local network IP ({meta['hostname']}), typical for routers or intranet devices.")
            recommendations.append("This is an internal private network address (RFC 1918) and does not represent an external phishing lure.")
        else:
            warnings.append("Raw public IP address used instead of a standard domain name.")
            recommendations.append("Verify the destination through official sources. Legitimate public services use registered domains.")
    else:
        positives.append("No IP address detected in the hostname; valid domain name used.")

    # 2. HTTPS indicators
    if features_dict["has_https"]:
        positives.append("HTTPS is enabled (connection traffic is encrypted).")
    else:
        warnings.append("URL uses insecure HTTP protocol (traffic is transmitted in plaintext).")
        recommendations.append("Check whether the website has an official HTTPS version. HTTPS alone does not guarantee legitimacy.")

    # 3. URL Length
    if features_dict["url_length"] > 75:
        warnings.append(f"Unusually long URL detected ({features_dict['url_length']} characters).")
    elif features_dict["url_length"] < 54:
        positives.append("URL length is within normal standard parameters.")

    # 4. Subdomains
    if features_dict["excessive_subdomains"]:
        warnings.append(f"Multiple nested subdomains detected ({features_dict['num_subdomains']} levels).")
        recommendations.append("Inspect the actual registered domain and look for misleading subdomains.")
    elif features_dict["num_subdomains"] <= 1:
        positives.append("URL structure appears normal with standard domain depth.")

    # 5. Shortener
    if features_dict["is_shortened"]:
        warnings.append("Suspicious URL shortening service detected that conceals the ultimate landing domain.")
        recommendations.append("Avoid expanding shortened links from untrusted sources; use a URL expander to preview.")
    else:
        positives.append("Direct destination link (no shortening disguise detected).")

    # 6. Keywords
    if features_dict["suspicious_keyword_count"] > 0:
        kw = ", ".join(meta["matched_keywords"])
        warnings.append(f"Suspicious phishing-associated keyword(s) detected: {kw}.")
        recommendations.append("Check the registered domain carefully before entering any sensitive information or credentials.")
    else:
        positives.append("No suspicious phishing keywords detected.")

    # 7. Brand spoofing
    if features_dict["misleading_brand_count"] > 0:
        brands = ", ".join(meta["matched_brands"])
        warnings.append(f"Potential brand spoofing pattern detected attempting to imitate '{brands}'.")
        recommendations.append(f"Do not log in. Navigate directly to the official homepage of {brands.capitalize()} instead.")

    # 8. Special characters & @
    if features_dict["has_at_symbol"]:
        warnings.append("Contains '@' symbol, which can mislead browsers into ignoring the leading domain text.")
        recommendations.append("Do not open links with '@' symbols. The browser may navigate to a domain after the '@'.")

    if features_dict["num_hyphens"] >= 3:
        warnings.append(f"Multiple hyphens detected in URL ({features_dict['num_hyphens']} hyphens), a common typosquatting tactic.")

    if features_dict["has_unusual_port"]:
        warnings.append(f"Unusual communication port specified ({meta.get('port')}).")

    if meta.get("tld") in SUSPICIOUS_TLDS:
        warnings.append(f"Top-level domain (.{meta['tld']}) is statistically associated with high phishing activity.")

    # Fallback recommendations if zero warnings
    if not warnings:
        recommendations.append("No major URL-based warning signs were identified. This does not guarantee that the website is safe. Verify important links through official sources.")
        recommendations.append("Remember that legitimate websites can be compromised; never enter credentials on unexpected prompts.")

    return warnings, positives, recommendations


FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_subdomains",
    "num_special_chars",
    "num_digits",
    "has_at_symbol",
    "is_ip_address",
    "is_shortened",
    "has_unusual_port",
    "has_https",
    "num_slash",
    "num_question",
    "num_equal",
    "num_percent",
    "suspicious_keyword_count",
    "domain_depth",
    "excessive_subdomains",
    "misleading_brand_count"
]
