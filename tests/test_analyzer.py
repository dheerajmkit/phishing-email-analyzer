"""Unit tests for header parsing and detectors (no network)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analyzer.headers import load_eml, header_summary, from_return_path_mismatch
from analyzer.detectors import display_name_spoof
from analyzer.auth import auth_results, auth_failed

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def test_legit_message_is_clean():
    msg = load_eml(os.path.join(SAMPLES, "legit.eml"))
    summary = header_summary(msg)
    assert not from_return_path_mismatch(summary)
    assert not display_name_spoof(summary)
    assert not auth_failed(auth_results(msg))


def test_suspicious_message_flags():
    msg = load_eml(os.path.join(SAMPLES, "suspicious.eml"))
    summary = header_summary(msg)
    assert display_name_spoof(summary)
    assert auth_failed(auth_results(msg))
