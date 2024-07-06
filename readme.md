# Web Application Security Report: OWASP Juice Shop

### 📄 [Report Markdown](report.md)  
### 🌐 [Report HTML](report.html)

## Summary

OWASP Juice Shop is an intentionally insecure web application written in Node.js, Express, and Angular. It includes vulnerabilities from the OWASP Top Ten and other security flaws found in real-world applications. This project serves as a learning guide for understanding and mitigating web application security issues.

This report is part of the `Web Application Security` course in the `Cybersecurity Specialization` in [Cesar School](https://cesar.school).

For more information on OWASP Juice Shop, visit the [official OWASP Juice Shop page](https://owasp.org/www-project-juice-shop/).

The report is inspired by the [penetration testing report template](https://labs.hackthebox.com/storage/press/samplereport/sample-penetration-testing-report-template.pdf) from HackTheBox.

## Installation

To set up OWASP Juice Shop locally, follow the instructions on the [official GitHub repository](https://github.com/juice-shop/juice-shop).

For Docker users, simply run:
```sh
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

## Assessment

This assessment includes identifying vulnerabilities, understanding exploitation techniques, evaluating their severity, and suggesting remediation strategies.

Each vulnerability is mapped to its corresponding [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/) and evaluated using the [Common Vulnerability Scoring System (CVSS)](https://www.first.org/cvss/) calculator.


## Tools

- [Burp Suite Community Edition](https://portswigger.net/burp)
- [JWT Editor Burp Extension](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
- [Sqlmap](https://sqlmap.org/)
- [CrackStation](https://crackstation.net/)
- [Hashcat](https://hashcat.net/)
- [JWT.io](https://jwt.io/)
- [FoxyProxy](https://getfoxyproxy.org/)
- [Firefox](https://www.mozilla.org/)
- [Docker](https://www.docker.com/)
- [Kali Linux](https://www.kali.org/)
- [Ubuntu](https://ubuntu.com/)
- [Windows Subsystem for Linux](https://learn.microsoft.com/windows/wsl/)


## Author
  
**Report by**: Pedro Coelho  
**Cesar School**  
**Specialization in Cybersecurity**  
**Web Application Security Course**  
**Instructor**: Petronio Lopes