"""URL and display-name spoofing detectors."""
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def extract_urls(msg):
    urls = set()
    for part in msg.walk():
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except Exception:
            continue
        urls.update(URL_RE.findall(body if isinstance(body, str) else ""))
    return sorted(urls)


def suspicious_urls(urls, trusted_domains):
    """Flag URLs whose registrable domain is outside the trusted set."""
    trusted = {d.lower() for d in trusted_domains}
    bad = []
    for url in urls:
        host = (urlparse(url).hostname or "").lower()
        if host and not any(host == t or host.endswith("." + t) for t in trusted):
            bad.append(url)
    return bad


def display_name_spoof(summary):
    """Flag when the display name looks like a brand but the address isn't."""
    display, addr = summary["from"]
    domain = addr.split("@")[-1].lower()
    brand_words = ("paypal", "microsoft", "apple", "amazon", "bank")
    if any(w in display.lower() for w in brand_words):
        return not any(w in domain for w in brand_words)
    return False
