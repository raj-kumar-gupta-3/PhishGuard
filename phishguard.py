import re
from urllib.parse import urlparse


def analyze_url(url):
    score = 0
    warnings = []

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    if not domain or "." not in domain:
        print("\nError: Invalid URL.")
        return

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

    print("\n" + "=" * 45)
    print("                 PHISHGUARD")
    print("=" * 45)
    print("Analyzing URL:", url)
    print()

    if warnings:
        print("Warnings:")
        for warning in warnings:
            print("  -", warning)
    else:
        print("No basic warning signs detected.")

    print("\n" + "-" * 45)
    print("Risk Score:", score)
    print("-" * 45)

    if score >= 4:
        print("Result: HIGH RISK")
    elif score >= 2:
        print("Result: SUSPICIOUS")
    else:
        print("Result: LOW RISK")

    print("=" * 45)


print("=" * 45)
print("           PHISHGUARD URL ANALYZER")
print("=" * 45)

url = input("Enter URL: ").strip()

if not url:
    print("\nError: Please enter a URL.")
else:
    analyze_url(url)