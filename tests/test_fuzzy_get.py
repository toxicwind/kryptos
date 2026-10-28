"""Fuzzy-label fallback: `get --label X` finds items when the exact label
misses (case / separator / suffix tolerant). Main-feature contract test."""
import json
import subprocess


def run(*args):
    return subprocess.run(
        ["secretsmith", *args], capture_output=True, text=True, timeout=60
    )


def test_fuzzy_get_case_insensitive():
    """Lowercased label resolves to the canonical keyring item."""
    r = run("get", "--label", "openrouter_api_key_1", "--show", "--json")
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["label"] == "OPENROUTER_API_KEY_1"
    assert data["secret"]


def test_fuzzy_get_separator_insensitive():
    """Dashes instead of underscores still resolve."""
    r = run("get", "--label", "OPENROUTER-API-KEY-1", "--show", "--json")
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["label"] == "OPENROUTER_API_KEY_1"


def test_fuzzy_get_substring():
    """Partial label (distinct enough) resolves via substring fallback."""
    r = run("get", "--label", "openrouter", "--show", "--json")
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["label"].startswith("OPENROUTER")


def test_fuzzy_get_no_match_errors():
    """Gibberish label still fails cleanly."""
    r = run("get", "--label", "zzz_no_such_secret_zzz", "--show", "--json")
    assert r.returncode != 0


def test_fuzzy_disabled_flag():
    """--no-fuzzy restores strict exact-label behavior."""
    r = run("get", "--label", "openrouter_api_key_1", "--no-fuzzy", "--show", "--json")
    assert r.returncode != 0
