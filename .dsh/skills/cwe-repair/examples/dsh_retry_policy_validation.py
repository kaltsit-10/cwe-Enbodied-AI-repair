#!/usr/bin/env python3
"""Validate the user-level DSH retry policy without making network requests."""
from pathlib import Path
import re
import sys

SETTINGS = Path(r"C:\Users\asus\.dsh\settings.yaml")
REQUIRED = {
    "timeoutMs": "120000",
    "streamIdleTimeoutMs": "600000",
    "maxRetries": "6",
    "initialDelayMs": "1500",
    "maxDelayMs": "30000",
}


def main():
    text = SETTINGS.read_text(encoding="utf-8")
    for key, value in REQUIRED.items():
        if not re.search(rf"^\s*{key}:\s*{re.escape(value)}\s*$", text, re.MULTILINE):
            raise SystemExit(f"missing or invalid {key}")
    if "retryPolicy:" not in text or "mode: normal" not in text:
        raise SystemExit("retry policy mode is not normal")
    if "openai:" not in text:
        raise SystemExit("openai provider is missing")
    print("dsh retry policy: PASS (1.5s initial, 30s cap, 6 retries, 120s request deadline)")


if __name__ == "__main__":
    main()
