from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import urlparse

import dns.exception
import dns.resolver


URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"
}
SUSPICIOUS_PHRASES = {
    "verify your account": "Requests account verification",
    "confirm your password": "Requests password confirmation",
    "suspended": "Mentions an account suspension",
    "immediately": "Uses urgency language",
    "urgent action": "Uses urgency language",
    "wire transfer": "Mentions a wire transfer",
    "gift card": "Requests or mentions gift cards",
    "claim your prize": "Promises a prize",
    "payment overdue": "Claims a payment is overdue",
}
AUTH_METHODS = ("spf", "dkim", "dmarc")
AUTH_STATUSES = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}


def _finding(category: str, title: str, detail: str, severity: str) -> dict[str, str]:
    return {
        "category": category,
        "title": title,
        "detail": detail,
        "severity": severity,
    }


def _clean_url(value: str) -> str:
    return value.rstrip(".,;:!?)]}")


def inspect_urls(text: str) -> tuple[list[dict[str, object]], list[dict[str, str]]]:
    results: list[dict[str, object]] = []
    findings: list[dict[str, str]] = []
    seen: set[str] = set()

    for match in URL_PATTERN.finditer(text):
        url = _clean_url(match.group(0))
        if not url or url in seen:
            continue
        seen.add(url)
        normalized = url if "://" in url else f"http://{url}"
        parsed = urlparse(normalized)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        flags: list[str] = []
        severity = "low"

        if parsed.scheme != "https":
            flags.append("Uses HTTP or has no explicit HTTPS scheme")
            severity = "medium"
        if hostname in SHORTENERS:
            flags.append("Uses a URL-shortening service")
            severity = "medium"
        try:
            ipaddress.ip_address(hostname)
            flags.append("Uses an IP address instead of a domain name")
            severity = "high"
        except ValueError:
            pass
        if "xn--" in hostname:
            flags.append("Contains an internationalized/punycode domain")
            severity = "high"
        if parsed.username or parsed.password:
            flags.append("Contains credentials in the URL")
            severity = "high"
        if any(word in parsed.path.lower() for word in ("login", "verify", "secure", "password", "account")):
            flags.append("Path contains an account or credential-related word")
            if severity == "low":
                severity = "medium"

        if flags:
            findings.append(
                _finding(
                    "url",
                    "Review a link before opening it",
                    f"{hostname or url}: " + "; ".join(flags),
                    severity,
                )
            )
        results.append({"url": url, "hostname": hostname, "severity": severity, "flags": flags})

    return results, findings


def _header_auth_results(raw_email: str) -> dict[str, str]:
    results: dict[str, str] = {}
    for name in ("authentication-results", "arc-authentication-results", "received-spf"):
        for header_value in re.findall(rf"(?im)^{re.escape(name)}\s*:\s*(.+(?:\n[ \t].+)*)", raw_email):
            normalized = re.sub(r"\s+", " ", header_value).lower()
            for method in AUTH_METHODS:
                match = re.search(rf"\b{method}\s*=\s*([a-z]+)", normalized)
                if match and match.group(1) in AUTH_STATUSES and method not in results:
                    results[method] = match.group(1)
            if name == "received-spf" and "spf" not in results:
                match = re.search(r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b", normalized)
                if match:
                    results["spf"] = match.group(1)
    return results


def _txt_lookup(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=1.5)
        return [b"".join(record.strings).decode("utf-8", errors="replace") for record in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.exception.DNSException, OSError):
        return []


def _dns_records(domain: str, selector: str | None, enabled: bool) -> dict[str, object]:
    empty = {"checked": False, "found": None, "records": []}
    if not enabled or not domain:
        return {method: dict(empty) for method in AUTH_METHODS}

    spf = [record for record in _txt_lookup(domain) if record.lower().startswith("v=spf1")]
    dmarc = [record for record in _txt_lookup(f"_dmarc.{domain}") if record.lower().startswith("v=dmarc1")]
    dkim: list[str] = []
    if selector:
        dkim = _txt_lookup(f"{selector}._domainkey.{domain}")

    return {
        "spf": {"checked": True, "found": bool(spf), "records": spf},
        "dkim": {
            "checked": bool(selector),
            "found": bool(dkim) if selector else None,
            "selector": selector,
            "records": dkim,
        },
        "dmarc": {"checked": True, "found": bool(dmarc), "records": dmarc},
    }


def analyze_sender_auth(sender: str, reply_to: str, raw_email: str, check_dns: bool) -> dict[str, object]:
    sender_address = parseaddr(sender)[1]
    reply_address = parseaddr(reply_to)[1]
    domain = sender_address.rsplit("@", 1)[-1].lower() if "@" in sender_address else ""
    reply_domain = reply_address.rsplit("@", 1)[-1].lower() if "@" in reply_address else ""
    selector_match = re.search(r"(?im)^dkim-signature\s*:[^\n]*?\bs=([^;\s]+)", raw_email)
    selector = selector_match.group(1).strip("\"'") if selector_match else None
    reported = _header_auth_results(raw_email)
    findings: list[dict[str, str]] = []

    if reply_domain and domain and reply_domain != domain:
        findings.append(
            _finding(
                "sender",
                "Reply-To domain differs from sender",
                f"From uses {domain}, while Reply-To uses {reply_domain}.",
                "medium",
            )
        )
    for method, status in reported.items():
        if status in {"fail", "softfail", "permerror"}:
            findings.append(
                _finding(
                    "sender",
                    f"{method.upper()} reported {status}",
                    "This status was read from the message's Authentication-Results or Received-SPF header; it was not independently verified.",
                    "high" if status in {"fail", "permerror"} else "medium",
                )
            )

    return {
        "sender_domain": domain or None,
        "reply_to_domain": reply_domain or None,
        "reported_by_headers": reported,
        "dns_records": _dns_records(domain, selector, check_dns),
        "findings": findings,
        "note": "Authentication-Results headers are reported as provided; this tool does not cryptographically verify DKIM signatures.",
    }


def analyze_content(subject: str, body: str, sender: str, reply_to: str = "", raw_email: str = "", check_dns: bool = False) -> dict[str, object]:
    full_text = f"{subject}\n{body}"
    findings: list[dict[str, str]] = []
    lowered = full_text.lower()
    for phrase, description in SUSPICIOUS_PHRASES.items():
        if phrase in lowered:
            findings.append(_finding("content", description, f"Matched phrase: “{phrase}”. This phrase alone does not prove an email is malicious.", "medium"))

    urls, url_findings = inspect_urls(full_text)
    findings.extend(url_findings)
    auth = analyze_sender_auth(sender, reply_to, raw_email, check_dns)
    findings.extend(auth["findings"])

    return {"urls": urls, "authentication": auth, "findings": findings}


def calculate_risk(findings: list[dict[str, str]], spam_score: float | None = None) -> tuple[int, str]:
    weights = {"low": 4, "medium": 12, "high": 23}
    score = sum(weights.get(item.get("severity", "low"), 0) for item in findings)
    if spam_score is not None:
        if spam_score >= 0.85:
            score += 20
        elif spam_score >= 0.65:
            score += 10
    score = min(100, score)
    level = "high" if score >= 55 else "medium" if score >= 25 else "low"
    return score, level

