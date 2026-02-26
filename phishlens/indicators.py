from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urlparse, unquote
import re
import ipaddress


# ---------- Paths (robusto em qualquer OS) ----------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"  # renomeie Data/ -> data/


# ---------- Loaders (cache simples) ----------
_CACHE: dict[str, list[str]] = {}


def _load_lines(filename: str) -> list[str]:
    key = filename
    if key in _CACHE:
        return _CACHE[key]

    path = DATA_DIR / filename
    if not path.exists():
        _CACHE[key] = []
        return _CACHE[key]

    lines: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            lines.append(s.lower())

    _CACHE[key] = lines
    return lines


def load_suspicious_tlds() -> set[str]:
    # arquivo sugerido: suspicious_tlds.txt (um tld por linha, sem ponto)
    return set(_load_lines("suspicious_tlds.txt"))


def load_shorteners() -> set[str]:
    # arquivo sugerido: shorteners.txt (um domínio por linha)
    return set(_load_lines("shorteners.txt"))


def load_legit_domains() -> list[str]:
    # arquivo sugerido: legit_domains.txt (um domínio por linha)
    # ex: google.com, microsoft.com...
    return _load_lines("legit_domains.txt")


def load_keywords() -> set[str]:
    # arquivo sugerido: keywords.txt (um keyword por linha)
    default = {
        "login", "signin", "verify", "verification", "secure", "account",
        "password", "update", "billing", "payment", "confirm", "support",
        "security", "auth", "oauth", "bank", "invoice"
    }
    file_words = set(_load_lines("keywords.txt"))
    return (file_words | default)


# ---------- Helpers ----------
HOMOGLYPHS = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t",
    "@": "a",
})


def normalize_host(host: str) -> str:
    """
    Normalize common leetspeak/homoglyphs for lookalike detection.
    Also strips trailing dot.
    """
    host = (host or "").strip().lower().rstrip(".")
    return host.translate(HOMOGLYPHS)


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def extract_hostname(netloc: str) -> tuple[str, int | None]:
    """
    netloc may include credentials, port, etc.
    Returns (host, port).
    """
    if not netloc:
        return "", None

    # Remove credentials user:pass@
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]

    host = netloc
    port = None

    # IPv6 in brackets
    if host.startswith("[") and "]" in host:
        end = host.index("]")
        host_part = host[1:end]
        rest = host[end + 1 :]
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except Exception:
                port = None
        return host_part.lower(), port

    # host:port
    if ":" in host:
        h, p = host.rsplit(":", 1)
        if p.isdigit():
            host = h
            port = int(p)

    return host.lower(), port


def get_tld(host: str) -> str:
    """
    Basic TLD extraction (last label). Not perfect for multi-part (co.uk),
    but good enough for heuristic signal.
    """
    if not host or is_ip(host):
        return ""
    parts = host.split(".")
    if len(parts) < 2:
        return ""
    return parts[-1].lower()


def subdomain_count(host: str) -> int:
    if not host or is_ip(host):
        return 0
    parts = host.split(".")
    # example: a.b.google.com -> subdomains = len(parts) - 2
    return max(0, len(parts) - 2)


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def looks_like_shortener(host: str, shorteners: set[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    return host in shorteners


def find_keywords(path: str, query: str, kw: set[str]) -> list[str]:
    text = f"{path} {query}".lower()
    hits = [k for k in kw if k in text]
    hits.sort()
    return hits


def find_typosquat(host: str, legit_domains: list[str]) -> list[dict]:
    """
    Compare host against legit domains using normalized forms.
    Returns top matches sorted by similarity desc.
    """
    if not host or is_ip(host):
        return []

    host = host.lower().rstrip(".")
    host_norm = normalize_host(host)

    results: list[dict] = []
    for legit in legit_domains:
        legit = legit.lower().rstrip(".")
        legit_norm = normalize_host(legit)

        sim_raw = similarity(host, legit)
        sim_norm = similarity(host_norm, legit_norm)

        # take best similarity between raw and normalized
        sim = max(sim_raw, sim_norm)

        # Only consider "close" matches
        if sim >= 0.90 and host != legit:
            results.append({
                "target": legit,
                "similarity": round(sim, 3),
                "normalized_match": (host_norm == legit_norm),
            })

    results.sort(key=lambda x: x["similarity"], reverse=True)
    return results[:3]


# ---------- Main collector ----------
def collect_indicators(url: str) -> dict:
    url = (url or "").strip()
    parsed = urlparse(url)

    valid_url = bool(parsed.scheme and parsed.netloc)
    host, port = extract_hostname(parsed.netloc)

    keywords = load_keywords()
    suspicious_tlds = load_suspicious_tlds()
    shorteners = load_shorteners()
    legit_domains = load_legit_domains()

    # Detect encoding/obfuscation
    decoded_path = unquote(parsed.path or "")
    decoded_query = unquote(parsed.query or "")
    has_encoded_chars = (decoded_path != (parsed.path or "")) or (decoded_query != (parsed.query or ""))

    tld = get_tld(host)
    suspicious_tld = (tld in suspicious_tlds) if tld else False

    has_punycode = ("xn--" in host) if host else False

    # Unusual port heuristic
    unusual_port = port is not None and port not in (80, 443)

    # Host dot patterns
    dots = host.count(".") if host else 0
    too_many_dots = dots >= 4

    # Path oddities
    contains_at = "@" in (url or "")
    has_double_slash_in_path = "//" in (parsed.path or "")[1:]  # ignore leading slash

    # Keywords
    kw_hits = find_keywords(parsed.path or "", parsed.query or "", keywords)

    # Typosquat
    typos = find_typosquat(host, legit_domains) if legit_domains else []

    # Shortener
    is_shortener = looks_like_shortener(host, shorteners)

    # URL length
    url_len = len(url)

    return {
        "url": url,
        "valid_url": valid_url,

        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "host": host,
        "port": port,

        "tld": tld,
        "suspicious_tld": suspicious_tld,
        "has_punycode": has_punycode,

        "uses_ip_host": is_ip(host) if host else False,
        "has_unusual_port": unusual_port,

        "subdomain_count": subdomain_count(host),
        "too_many_dots": too_many_dots,

        "url_length": url_len,
        "has_encoded_chars": has_encoded_chars,
        "contains_at_symbol": contains_at,
        "has_double_slash_in_path": has_double_slash_in_path,

        "suspicious_keywords": kw_hits,

        "is_shortener": is_shortener,
        "typosquat_matches": typos,
    }