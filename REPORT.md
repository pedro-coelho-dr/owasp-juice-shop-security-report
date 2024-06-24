# OWASP Juice Shop Web Application Security Report

## Summary

This report presents a security assessment of the [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), an intentionally insecure web application. The assessment includes identifying vulnerabilities, understanding exploitation techniques, evaluating their severity, and suggesting remediation strategies.

Each vulnerability is mapped to its corresponding [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/) and evaluated using the [Common Vulnerability Scoring System (CVSS)](https://www.first.org/cvss/) calculator.


## Tools

- [Burp Suite Community Edition](https://portswigger.net/burp)
- [Sqlmap](https://sqlmap.org/)
- [CrackStation](https://crackstation.net/)
- [FoxyProxy](https://getfoxyproxy.org/)
- [Firefox](https://www.mozilla.org/)
- [VSCode](https://code.visualstudio.com/)
- [Docker](https://www.docker.com/)
- [Kali Linux](https://www.kali.org/)
- [Ubuntu](https://ubuntu.com/)
- [Windows Subsystem for Linux](https://learn.microsoft.com/windows/wsl/)

## Reconnaissance

### Burp Suite -> Target -> Site map

![alt text](img/mapping-burp.png)

---

### 1 - Directory Listing Exposure in '/ftp'

By accessing the `/ftp` directory directly, files available for download can be seen. 

![alt text](img/mapping-ftp.png)

For example, the `acquisitions.md` file contains sensitive information about the company's acquisitions.

![alt text](img/mapping-acquisitions.png)

**CWE ID**:
- [CWE-538: File and Directory Information Exposure](https://cwe.mitre.org/data/definitions/538.html)

**Severity**: 7.5 (High) - Unauthorized access to sensitive company information.

![alt text](img/mapping-ftp-score.png)

**Remediation**: Implement proper access control and disable directory listing.

---

### 2. Sensitive Data Exposure in Main.js

Inspecting `main.js` in the developer tools debugger with Pretty Print reveals critical internal information. 

![alt text](img/mapping-mainjs.png)

For instance, searching for 'admin' exposes the administration panel, which may displays user information and customer feedback control.

![alt text](img/mapping-admin-panel.png)

**CWE ID**:
- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

**Severity**: 5.3 (Medium) - Exposure of internal endpoints and application logic.

![alt text](img/mapping-mainjs-score.png)

**Remediation**: Minimize information exposure in client-side code and use obfuscation where possible.



## SQL Injection

### 3 - Brute Force SQL Injection Admin Login Bypass

The login form is vulnerable to SQL injection. By entering `' OR 1=1 --` in the Email field and anything in the password field, the application logs in as the first user in the database (the admin user). By exploiting this vulnerability, the attacker can escalate privileges, gaining administrative access to the application and enabling multiple further attacks.

![alt text](img/sqlinjection-admin-login.png)

Using Burp Suite Intruder tool configured with a [list](https://book.hacktricks.xyz/pentesting-web/login-bypass/sql-login-bypass) of SQL Injection payloads to automate and test the vulnerability in the login form.

![alt text](img/sqlinjection-admin-bruteforce.png)


**CWE ID**: 
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)


**Severity**: 10 (Critical) - Potential to gain administrative access to the application.

![alt text](img/sqlinjection-admin-score.png)

**Remediation**: Implement parameterized queries and use prepared statements.

---

### 4 - SQL Injection in Product Search

The search field in the application is vulnerable to SQL injection. By using tools like Burp Suite and [sqlmap](https://sqlmap.org/), the entire database schema and data were collected. This included registered [credit cards](db/Cards.csv) in plain text and all [users](db/Users.csv) information, although passwords were encrypted.

![alt text](img/sqlinjection2-endpointburp.png)

![alt text](img/sqlinjection2-sqlmap.png)

![alt text](img/sqlinjection2-tables.png)

![alt text](img/sqlinjection2-cards.png)

![alt text](img/sqlinjection2-users.png)

**CWE ID**: 
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

**Severity**: 9.8 (Critical) - Full database access and data exfiltration.

![alt text](img/sqlinjection2-score.png)

**Remediation**: Use parameterized queries, validate and sanitize inputs, and implement robust access controls.

## Weak Cryptography

### 5 - Weak Password Hashing (MD5)

By examining the user table, it was detected that the password hashes are stored using the MD5 hashing algorithm. Using a rainbow table attack via the online tool [CrackStation](https://crackstation.net/), 4 passwords were successfully decrypted. Further research and use of more comprehensive rainbow tables could potentially lead to the decryption of more passwords.

![alt text](img/weakcrypto-rainbow.png)

**CWE ID**:
- [CWE-328: Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

**Severity**:  9.1 (Critical) - Unauthorized access to user and admin accounts through password decryption.

![CVSS Score](img/weakcrypto-score.png)

**Remediation**: Replace MD5 with a more secure hashing algorithm. Additionally, implement salting and peppering techniques to enhance password security.


## Cross-Site Request Forgery

### 6 - Cross-Site Request Forgery (CSRF) in Change Password Functionality



During the assessment, it was identified that the change password functionality is vulnerable to CSRF attacks. Using Burp Suite's Repeater tool, the password could be changed directly by altering the request. When the current password value was set incorrectly, it led to an error. However, by removing the current password value, the password change was successfully executed, allowing the attacker to change the password without knowing the actual current password.


![alt text](img/csrf-1.png)

The request with the correct current password successfully changes the password.

![alt text](img/csrf-2.png)

The request with an incorrect current password leads to an error.

![alt text](img/csrf-3.png)

The request without the current password value successfully changes the password.


Obs.: The vulnerability did not work on an updated version of Firefox due to built-in browser protections, making it harder to reproduce the attack on a victim's computer. However, other methods, such as using Burp Suite, older browsers, or custom scripts, could still be used to exploit this vulnerability.

**CWE ID**:
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

**Severity**: 8.0 (High) - Unauthorized actions performed on behalf of authenticated users.

![alt text](img/csrf-score.png)

**Remediation**: Implement anti-CSRF tokens to validate the authenticity of requests. Ensure that all state-changing requests require a unique token that is verified on the server-side.

---

## Cross Site Scripting

Colocar o produto negativo para add a wallet


### /rest/products/1/reviews
