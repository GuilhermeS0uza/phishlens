from .indicators import collect_indicators
from .scoring import score_indicators
from .safebrowsing import check_url


def analyze_url(url: str) -> dict:
    indicators = collect_indicators(url)

    # Safe Browsing enrichment (non-blocking)
    sb = check_url(url)
    indicators["safe_browsing"] = sb

    return score_indicators(indicators)


def analyze_many(urls: list[str]) -> list[dict]:
    return [analyze_url(u) for u in urls]