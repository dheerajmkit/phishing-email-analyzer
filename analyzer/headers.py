"""Email header parsing and Received-chain analysis."""
import email
from email import policy
from email.utils import parseaddr


def load_eml(path):
    with open(path, "rb") as fh:
        return email.message_from_binary_file(fh, policy=policy.default)


def header_summary(msg):
    """Return the triage-relevant headers as a plain dict."""
    addr = lambda h: parseaddr(msg.get(h, ""))  # noqa: E731
    return {
        "from": addr("From"),
        "reply_to": addr("Reply-To"),
        "return_path": parseaddr(msg.get("Return-Path", "")),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "received_count": len(msg.get_all("Received", [])),
    }


def received_hops(msg):
    """Return the Received headers in arrival order (oldest first)."""
    return list(reversed(msg.get_all("Received", [])))


def from_return_path_mismatch(summary):
    """True when the envelope sender differs from the From domain."""
    from_domain = summary["from"][1].split("@")[-1].lower()
    rp_domain = summary["return_path"][1].split("@")[-1].lower()
    return bool(from_domain and rp_domain and from_domain != rp_domain)
