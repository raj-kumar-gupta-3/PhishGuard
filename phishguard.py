import re
import sys
from urllib.parse import urlparse


def analyze_url(url):
    score = 0
    warnings = []

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    if not domain or "." not in domain:
        return {
            "url": url,
            "score": 0,
            "warnings": ["Invalid URL"],
            "result": "INVALID"
        }

    if parsed.scheme != "https":
        score += 1
        warnings.append("URL does not use HTTPS")

    if len(url) > 75:
        score += 1
        warnings.append("URL is unusually long")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        score += 2
        warnings.append("URL uses an IP address")

    suspicious_words = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "password",
        "confirm"
    ]

    for word in suspicious_words:
        if word in url.lower():
            score += 1
            warnings.append(f"Suspicious keyword found: {word}")
            break

    if "@" in url:
        score += 2
        warnings.append("URL contains @ symbol")

    if url.count(".") > 4:
        score += 1
        warnings.append("Many subdomains/dots detected")

    if score >= 4:
        result = "HIGH RISK"
    elif score >= 2:
        result = "SUSPICIOUS"
    else:
        result = "LOW RISK"

    return {
        "url": url,
        "score": score,
        "warnings": warnings,
        "result": result
    }


def display_result(result):
    print("\n" + "=" * 45)
    print("           PHISHGUARD URL ANALYZER")
    print("=" * 45)
    print("Analyzing URL:", result["url"])
    print()

    if result["result"] == "INVALID":
        print("Error: Invalid URL.")
        print("=" * 45)
        return

    if result["warnings"]:
        print("Warnings:")
        for warning in result["warnings"]:
            print("  -", warning)
    else:
        print("No basic warning signs detected.")

    print("\n" + "-" * 45)
    print("Risk Score:", result["score"])
    print("-" * 45)
    print("Result:", result["result"])
    print("=" * 45)


def main():
    if len(sys.argv) > 1:
        url = sys.argv[1].strip()
    else:
        url = input("Enter URL: ").strip()

    if not url:
        print("Error: Please enter a URL.")
        return

    result = analyze_url(url)
    display_result(result)


if __name__ == "__main__":
    main()