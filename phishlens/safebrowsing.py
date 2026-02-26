from __future__ import annotations

import json
import os
import socket
from urllib import request, error
from typing import Any

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"

# Defaults suggested by Safe Browsing docs examples
DEFAULT_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
DEFAULT_PLATFORM_TYPES = ["ANY_PLATFORM"]
DEFAULT_THREAT_ENTRY_TYPES = ["URL"]


def get_api_key() -> str | None:
    key = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
    return key or None


def check_url(url: str, timeout_seconds: float = 5.0) -> dict[str, Any]:
    """
    Returns:
      {
        "enabled": bool,
        "ok": bool,
        "matches": list[dict],
        "error": str|None
      }
    """
    api_key = get_api_key()
    if not api_key:
        return {"enabled": False, "ok": True, "matches": [], "error": None}

    body = {
        "client": {
            "clientId": "phishlens",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": DEFAULT_THREAT_TYPES,
            "platformTypes": DEFAULT_PLATFORM_TYPES,
            "threatEntryTypes": DEFAULT_THREAT_ENTRY_TYPES,
            "threatEntries": [{"url": url}],
        }
    }

    req = request.Request(
        SAFE_BROWSING_ENDPOINT.format(key=api_key),
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=timeout_seconds) as resp:
            raw = resp.read().decode("utf-8")
            data = json.loads(raw) if raw else {}
            matches = data.get("matches", []) or []
            return {"enabled": True, "ok": True, "matches": matches, "error": None}

    except error.HTTPError as e:
        # Rate limit / key issues / etc.
        try:
            detail = e.read().decode("utf-8", errors="ignore")
        except Exception:
            detail = ""
        msg = f"HTTP {e.code}"
        if e.code == 429:
            msg = "HTTP 429 (rate limited)"
        elif e.code == 403:
            msg = "HTTP 403 (forbidden - check API key / API enabled)"
        elif e.code == 400:
            msg = "HTTP 400 (bad request)"
        if detail:
            msg += f" - {detail[:180]}"
        return {"enabled": True, "ok": False, "matches": [], "error": msg}

    except (error.URLError, socket.timeout) as e:
        return {"enabled": True, "ok": False, "matches": [], "error": f"Network/timeout error: {e}"}

    except Exception as e:
        return {"enabled": True, "ok": False, "matches": [], "error": f"Unexpected error: {e}"}