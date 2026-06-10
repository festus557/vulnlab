# VulnLab - Intentionally Vulnerable Web Application

> **⚠️ WARNING: This application is intentionally vulnerable. Do NOT deploy on public servers or expose to untrusted networks. For educational and authorized testing purposes only.**

## Overview

VulnLab is a deliberately vulnerable web application built with Python Flask for security training and education. It contains common web vulnerabilities aligned with the OWASP Top 10.

## Vulnerabilities Included

| Vulnerability | Difficulty | Endpoint |
|---|---|---|
| SQL Injection | Low | `/sql-injection` |
| Cross-Site Scripting (XSS) | Low | `/xss` |
| Command Injection | Medium | `/command-injection` |
| Local File Inclusion (LFI) | Medium | `/lfi` |
| Unrestricted File Upload | High | `/file-upload` |
| Insecure Direct Object Reference (IDOR) | Low | `/idor` |
| Cross-Site Request Forgery (CSRF) | Medium | `/csrf` |
| Insecure Deserialization | High | `/deserialization` |
| Server-Side Request Forgery (SSRF) | Medium | `/ssrf` |
| XML External Entity (XXE) | High | `/xxe` |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/festus557/vulnlab.git
cd vulnlab

# Run setup
chmod +x setup.sh
./setup.sh

# Or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Access the application at `http://localhost:5000`

## Default Credentials

| Username | Password | Role |
|---|---|---|
| admin | admin123 | admin |
| john | password | user |
| jane | letmein | user |

## API Endpoints

- `GET /api/user?username=<name>` - Get user info (SQLi vulnerable)
- `GET /api/search?q=<query>` - Search comments (SQLi vulnerable)

## Learning Objectives

Each vulnerability page includes:
- A working vulnerable implementation
- Hints to guide exploitation
- Prevention recommendations

## Disclaimer

This application is for **educational purposes only**. The vulnerabilities are intentional and are designed to teach secure coding practices. Never use these techniques against systems you don't own or have explicit permission to test.

## License

MIT License - See LICENSE file for details.
