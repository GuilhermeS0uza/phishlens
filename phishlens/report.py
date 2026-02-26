import json
from datetime import datetime

def print_report(result: dict) -> None:
    url = result["url"]
    score = result["score"]
    label = result["label"]
    reasons = result["reasons"]

    print(f"[{label}] score={score:>3}  url={url}")
    for r in reasons:
        print(f"  - {r}")

def save_json(results: list[dict], out_path: str) -> None:
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "results": results,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)