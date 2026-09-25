# 🛡️ PhishGuard

PhishGuard is a beginner-friendly Python project that analyzes URLs for common phishing-related warning signs.

This project was created to practice Python programming, URL parsing, regular expressions, and basic web security concepts.

## Features

* HTTPS check
* URL length check
* IP address detection
* Suspicious keyword detection
* `@` symbol detection
* Multiple subdomain/dot detection
* Basic risk scoring
* Invalid URL handling
* Automated tests using Python `unittest`

## Technologies

* Python 3
* Regular Expressions
* `urllib.parse`
* `unittest`

## Project Structure

```text
PhishGuard/
├── phishguard.py
├── README.md
├── .gitignore
└── tests/
    ├── __init__.py
    └── test_phishguard.py
```

## Installation

Clone the repository:

```bash
git clone https://github.com/raj-kumar-gupta-3/PhishGuard.git
cd PhishGuard
```

No external Python packages are required.

## Usage

Run PhishGuard with:

```bash
python3 phishguard.py
```

Enter a URL when prompted:

```text
Enter URL: https://example.com
```

PhishGuard will display detected warning signs, a basic risk score, and a result.

## Running Tests

Run the automated tests with:

```bash
python3 -m unittest discover -s tests -v
```

The project currently includes tests for:

* HTTPS URLs
* HTTP URLs
* IP addresses
* Suspicious keywords
* `@` symbol
* Invalid URLs

## Important Note

PhishGuard uses simple heuristic checks for educational purposes.

A low-risk result does **not** guarantee that a website is safe, and a high-risk result does **not** prove that a website is malicious.

Do not use this tool as a replacement for professional security tools or security analysis.

## Learning Goal

This project is part of my journey to learn:

**Learn → Practice → Build → Test → Document → Improve**

## Author

**Raj Kumar Gupta**

BCA Student | Aspiring Cybersecurity Professional
