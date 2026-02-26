def _clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, n))


def score_indicators(ind: dict) -> dict:
    score = 0
    reasons: list[str] = []

    if not ind.get("valid_url"):
        return {
            "url": ind.get("url"),
            "score": 100,
            "label": "DANGEROUS",
            "reasons": ["Invalid or malformed URL"],
            "indicators": ind,
        }

    # --- URL shortener ---
    if ind.get("is_shortener"):
        score += 20
        reasons.append("URL shortener detected (hides final destination)")

    # --- IP host ---
    if ind.get("uses_ip_host"):
        score += 25
        reasons.append("Host is an IP address (common phishing technique)")

    # --- Unusual port ---
    if ind.get("has_unusual_port"):
        score += 10
        reasons.append(f"Unusual port used: {ind.get('port')}")

    # --- Suspicious TLD / Punycode ---
    tld = (ind.get("tld") or "").lower()
    if tld:
        if tld.startswith("xn--"):
            score += 15
            reasons.append("Internationalized (punycode) TLD detected — homograph risk")
        elif ind.get("suspicious_tld"):
            score += 10
            reasons.append(f"Suspicious or abused TLD detected: .{tld}")

    if ind.get("has_punycode"):
        score += 6
        reasons.append("Punycode detected in hostname (possible homograph attack)")

    # --- Encoded chars ---
    if ind.get("has_encoded_chars"):
        score += 8
        reasons.append("Encoded characters found (possible URL obfuscation)")

    # --- URL length ---
    if ind.get("url_length", 0) >= 90:
        score += 8
        reasons.append("Very long URL (possible obfuscation)")

    # --- Subdomain abuse ---
    if ind.get("subdomain_count", 0) >= 3:
        score += 10
        reasons.append("Multiple subdomains detected (possible brand impersonation)")

    # --- Too many dots ---
    if ind.get("too_many_dots"):
        score += 8
        reasons.append("Excessive dots in hostname (suspicious structure)")

    # --- @ symbol ---
    if ind.get("contains_at_symbol"):
        score += 15
        reasons.append("URL contains '@' symbol (can mislead users)")

    # --- Double slash in path ---
    if ind.get("has_double_slash_in_path"):
        score += 8
        reasons.append("Double '//' found in URL path (possible deception)")

    # --- Suspicious keywords ---
    keywords = ind.get("suspicious_keywords") or []
    if keywords:
        add = min(12, 3 * len(keywords))
        score += add
        reasons.append(f"Suspicious keywords found in path/query: {', '.join(keywords)}")

    # --- Typosquatting / Lookalike (peso forte) ---
    matches = ind.get("typosquat_matches") or []
    if matches:
        best = matches[0]
        sim = float(best.get("similarity", 0))
        normalized_match = bool(best.get("normalized_match"))

        # If normalized forms match exactly, treat as very strong phishing signal
        if normalized_match:
            score += 45
            reasons.append(
                f"Lookalike domain via homoglyph/leet substitution: resembles {best['target']} (similarity {best['similarity']})"
            )
        else:
            if sim >= 0.99:
                score += 35
            elif sim >= 0.93:
                score += 25
            elif sim >= 0.90:
                score += 18
            else:
                score += 12

            reasons.append(
                f"Possible typosquatting: looks like {best['target']} (similarity {best['similarity']})"
            )

    # --- Safe Browsing (Google) ---
    sb = ind.get("safe_browsing") or {}
    if sb.get("enabled") and not sb.get("ok"):
        score += 5
        reasons.append(f"Safe Browsing check failed: {sb.get('error')}")

    sb_matches = sb.get("matches") or []
    if sb_matches:
        # Strong signal: known malicious
        score = max(score, 85)
        threat_types = sorted({m.get("threatType", "UNKNOWN") for m in sb_matches})
        reasons.append(f"Safe Browsing match: {', '.join(threat_types)}")

    score = _clamp(score)

    if score >= 70:
        label = "DANGEROUS"
    elif score >= 35:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    return {
        "url": ind.get("url"),
        "score": score,
        "label": label,
        "reasons": reasons if reasons else ["No obvious phishing indicators detected"],
        "indicators": ind,
    }