"""Triage verdict: combine signals into a single report."""
from .headers import header_summary, from_return_path_mismatch
from .detectors import extract_urls, suspicious_urls, display_name_spoof
from .auth import auth_results, auth_failed


def triage(msg, trusted_domains):
    summary = header_summary(msg)
    urls = extract_urls(msg)
    auth = auth_results(msg)

    signals = {
        "from_return_path_mismatch": from_return_path_mismatch(summary),
        "display_name_spoof": display_name_spoof(summary),
        "suspicious_urls": suspicious_urls(urls, trusted_domains),
        "auth_failed": auth_failed(auth),
    }
    score = sum([
        signals["from_return_path_mismatch"],
        signals["display_name_spoof"],
        bool(signals["suspicious_urls"]),
        signals["auth_failed"],
    ])
    verdict = "clean" if score == 0 else "suspicious" if score == 1 else "likely phishing"
    return {"summary": summary, "signals": signals, "score": score, "verdict": verdict}


def print_report(report):
    print(f"Verdict: {report['verdict'].upper()} (score {report['score']}/4)")
    for name, value in report["signals"].items():
        print(f"  - {name}: {value}")
