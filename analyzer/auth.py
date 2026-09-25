"""SPF / DKIM / DMARC result parsing from Authentication-Results."""
import re

RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)


def auth_results(msg):
    """Return {mechanism: result} from Authentication-Results headers."""
    results = {}
    for header in msg.get_all("Authentication-Results", []):
        for mechanism, result in RESULT_RE.findall(header):
            results[mechanism.lower()] = result.lower()
    return results


def auth_failed(results):
    """True when any reported mechanism explicitly failed."""
    return any(v == "fail" for v in results.values())
