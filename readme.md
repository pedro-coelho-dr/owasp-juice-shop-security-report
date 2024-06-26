# Web Application Security Report: OWASP Juice Shop

<< **[HTML Preview](https://htmlpreview.github.io/?https://github.com/pedro-coelho-dr/owasp-juice-shop-security-report/blob/ee1dfdd539d61a1f9ca8ce889aafa070224517e8/report.html)** >>

### Contents
- [Web Application Security Report: OWASP Juice Shop](#web-application-security-report-owasp-juice-shop)
    - [Contents](#contents)
  - [Summary](#summary)
  - [Tools](#tools)
  - [1 - Directory Listing Exposure in '/ftp'](#1---directory-listing-exposure-in-ftp)
  - [2 - Sensitive Data Exposure in Main.js](#2---sensitive-data-exposure-in-mainjs)
  - [3 - SQL Injection Brute Force in User Login](#3---sql-injection-brute-force-in-user-login)
  - [4 - SQL Injection in Product Search](#4---sql-injection-in-product-search)
  - [5 - Weak Password Hashing (MD5)](#5---weak-password-hashing-md5)
  - [6 - Cross-Site Request Forgery (CSRF) in Change Password Functionality](#6---cross-site-request-forgery-csrf-in-change-password-functionality)
  - [7 - DOM XSS in Product Search](#7---dom-xss-in-product-search)
  - [8 - Broken Access Control in Basket Functionality](#8---broken-access-control-in-basket-functionality)
  - [9 - Improper Input Validation in Basket Functionality](#9---improper-input-validation-in-basket-functionality)
  - [10 - Improper Input Validation in File Upload Functionality](#10---improper-input-validation-in-file-upload-functionality)


## Summary

OWASP Juice Shop is an intentionally insecure web application written in Node.js, Express, and Angular. It includes vulnerabilities from the OWASP Top Ten and other security flaws found in real-world applications. This project serves as a learning guide for understanding and mitigating web application security issues.

This report is part of the `Web Application Security` course in the `Cybersecurity Specialization` in [Cesar School](https://cesar.school).

For more information on OWASP Juice Shop, visit the [official OWASP Juice Shop page](https://owasp.org/www-project-juice-shop/).

**Installation**

To set up OWASP Juice Shop locally, follow the instructions on the [official GitHub repository](https://github.com/juice-shop/juice-shop).

For Docker users, simply run:
```sh
docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop
```

**Assessment**

This assessment includes identifying vulnerabilities, understanding exploitation techniques, evaluating their severity, and suggesting remediation strategies.

Each vulnerability is mapped to its corresponding [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/) and evaluated using the [Common Vulnerability Scoring System (CVSS)](https://www.first.org/cvss/) calculator.


## Tools

- [Burp Suite Community Edition](https://portswigger.net/burp)
- [Sqlmap](https://sqlmap.org/)
- [CrackStation](https://crackstation.net/)
- [FoxyProxy](https://getfoxyproxy.org/)
- [Firefox](https://www.mozilla.org/)
- [Docker](https://www.docker.com/)
- [Kali Linux](https://www.kali.org/)
- [Ubuntu](https://ubuntu.com/)
- [Windows Subsystem for Linux](https://learn.microsoft.com/windows/wsl/)

## 1 - Directory Listing Exposure in '/ftp'

Burp Suite was used to map the application's endpoints. By navigating through the site map, the `/ftp` directory was discovered, which allows directory listing. This exposes sensitive information about the application's internal structure and files

![alt text](img/mapping-burp.png)

- By accessing the `/ftp` directory directly, files available for download can be seen. 

    ![alt text](img/mapping-ftp.png)

- For example, the `acquisitions.md` file contains sensitive information about the company's acquisitions.

    ![alt text](img/mapping-acquisitions.png)

**CWE ID**:
- [CWE-538: File and Directory Information Exposure](https://cwe.mitre.org/data/definitions/538.html)

**Severity**: 7.5 (High) - Unauthorized access to sensitive company information.

![alt text](img/mapping-ftp-score.png)

**Remediation**: Implement proper access control and disable directory listing.


## 2 - Sensitive Data Exposure in Main.js

Inspecting `main.js` in the developer tools debugger with Pretty Print reveals critical internal information. 

![alt text](img/mapping-mainjs.png)

- For instance, searching for 'admin' exposes the administration panel, which may displays user information and customer feedback control.

    ![alt text](img/mapping-admin-panel.png)

**CWE ID**:
- [CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

**Severity**: 5.3 (Medium) - Exposure of internal endpoints and application logic.

![alt text](img/mapping-mainjs-score.png)

**Remediation**: Minimize information exposure in client-side code and use obfuscation where possible.

## 3 - SQL Injection Brute Force in User Login

The login form is vulnerable to SQL injection. By entering `' OR 1=1 --` in the Email field and anything in the password field, the application logs in as the first user in the database (the admin user). By exploiting this vulnerability, the attacker can escalate privileges, gaining administrative access to the application and enabling multiple further attacks.

![alt text](img/sqlinjection-admin-login.png)

- Using Burp Suite Intruder tool configured with a [list](https://book.hacktricks.xyz/pentesting-web/login-bypass/sql-login-bypass) of SQL Injection payloads to automate and test the vulnerability in the login form.

    ![alt text](img/sqlinjection-admin-bruteforce.png)


**CWE ID**: 
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)


**Severity**: 10 (Critical) - Potential to gain administrative access to the application.

![alt text](img/sqlinjection-admin-score.png)

**Remediation**: Implement parameterized queries and use prepared statements.


## 4 - SQL Injection in Product Search

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

## 5 - Weak Password Hashing (MD5)

By examining the user table, it was detected that the password hashes are stored using the MD5 hashing algorithm. Using a rainbow table attack via the online tool [CrackStation](https://crackstation.net/), 4 passwords were successfully decrypted. Further research and use of more comprehensive rainbow tables could potentially lead to the decryption of more passwords.

![alt text](img/weakcrypto-rainbow.png)

**CWE ID**:
- [CWE-328: Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

**Severity**:  9.1 (Critical) - Unauthorized access to user and admin accounts through password decryption.

![CVSS Score](img/weakcrypto-score.png)

**Remediation**: Replace MD5 with a more secure hashing algorithm. Additionally, implement salting and peppering techniques to enhance password security.

## 6 - Cross-Site Request Forgery (CSRF) in Change Password Functionality

The change password functionality is vulnerable to CSRF attacks. Using Burp Suite's Repeater tool, the password could be changed directly by altering the request. When the current password value was set incorrectly, it led to an error. However, by removing the current password value, the password change was successfully executed, allowing the attacker to change the password without knowing the actual current password.

- The request with the correct current password successfully changes the password:

    ![alt text](img/csrf-1.png)


- The request with an incorrect current password leads to an error:❌

    ![alt text](img/csrf-2.png)

- The request without the current password value successfully changes the password: ✅

    ![alt text](img/csrf-3.png)


Obs.: The vulnerability did not work on an updated version of Firefox due to built-in browser protections, making it harder to reproduce the attack on a victim's computer. However, other methods, such as using Burp Suite, older browsers, or custom scripts, could still be used to exploit this vulnerability.

**CWE ID**:
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

**Severity**: 8.0 (High) - Unauthorized actions performed on behalf of authenticated users.

![alt text](img/csrf-score.png)

**Remediation**: Implement anti-CSRF tokens to validate the authenticity of requests. Ensure that all state-changing requests require a unique token that is verified on the server-side.

## 7 - DOM XSS in Product Search

The product search functionality is vulnerable to DOM-based XSS. DOM-based XSS occurs when the attack payload is executed as part of the Document Object Model (DOM) on the client side, without any interaction with the server. 

By entering the payload in the browser´s search bar, the application executes the script in the context of the user's browser.

**Payloads:**

1. **Basic Script Alert** ❌
    ```html
    <script>alert('XSS');</script>
    ```
    This payload did not work as the script was sanitized.

2. **Image Tag with onerror Attribute** ✅
    ```html
    <img src=x onerror=alert('XSS')>
    ```
    This payload triggered an alert box, demonstrating the presence of an XSS vulnerability.

    ![alt text](img/xss-dom-alert.png)

3. **Simple Redirect Link** ✅
    ```html
    <a href="https://cesar.school/">Clique</a>
    ```
    This payload created a link that, when clicked, redirected the user to another page.

    ![alt text](img/xss-dom-redirect.png)

4. **Image Tag with onerror Redirect** ✅
    ```html
    <img src=x onerror="window.location='https://cesar.school'">
    ```
    This payload straight redirected the user upon triggering the onerror event.

5. **Cookie Stealing** ✅
   ```html
    <iframe src="javascript:alert(document.cookie)">
    ```
    This payload triggered an alert showing the user's cookies.

    ![alt text](img/xss-dom-cookie.png)

**CWE ID**:
- [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

**Severity**: 5.4 (Medium) - Potential to execute arbitrary JavaScript in the user's browser.

![alt text](img/xss-dom-score.png)

**Remediation**: 
Implement proper input validation and output encoding.
Use security libraries and frameworks that handle these issues automatically.

## 8 - Broken Access Control in Basket Functionality

The basket functionality has broken access control vulnerabilities, allowing unauthorized actions on behalf of other users.

**View other users baskets**

By manipulating the request to view a basket, it was possible to access other users baskets. Using Burp Suite's Repeater tool, the HTTP header was modified to `/rest/basket/*`, with `*` being the user ID. This allowed viewing the contents of other users' baskets.

- Original request:

    ![alt text](img/broken-request-original.png)

- Altered request:

    ![alt text](img/broken-request-altered.png)

- Reponse
  
  The response shows the basket of the user with ID 2:

    ![alt text](img/broken-response.png)

Jim's basket was accessed, revealing his items and personal information.

![alt text](img/broken-site.png)


**Add items to other users baskets**

It was possible to add items to other users baskets by manipulating the request to add an item. This involved intercepting the request and altering the BasketId parameter.

- Original request:

    User `admin`
    
    BasketId `1`

    Product `Eggfruit Juice`
    
    ProductId `3`

    ![alt text](img/broken-add-request-original.png)
    
Trying to simply change the `BasketId` to `2` didn´t work, but adding a duplicated `BasketId` parameter with the value `2` worked.

- Altered request:
  
    User `Jim`

    BasketId `2`

    Quantity `10`

    ![alt text](img/broken-add-request-altered.png)

- Successful Response:
  
    ![alt text](img/broken-add-response.png)
   

Attempting to add more items to the basket on basket page using a `PUT` request or using Burp Suite's Repeater tool were unsuccessful. The vulnerability could only be exploited through the "Add to Basket" functionality on the main page by intercepting and modifying the request.

![alt text](img/broken-add-site.png)


**CWE ID**:
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

**Severity**: 8.1 (High) - Unauthorized actions performed on behalf of other users, including viewing and modifying basket contents.

![alt text](img/broken-add-score.png)

**Remediation**: 
Implement proper access control checks on both server-side and client-side.
Validate user permissions for each action to ensure users can only access and modify their own resources.

## 9 - Improper Input Validation in Basket Functionality

The basket functionality is vulnerable to improper input validation. By entering a negative quantity in the basket the application allows the user to proceed with the purchase, resulting in a negative total price.

- Original request:

    ![alt text](img/input-request-original.png)


- Altered request:

    Quantity `-10`

    ![alt text](img/input-request-altered.png)

- Successful Response:

    ![alt text](img/input-response.png)

The application allowed the purchase of a negative quantity of items, resulting in a negative total price.
![alt text](img/input-basket.png)

By checking out with a negative quantity using de digital wallet functionality, the user receives money instead of paying for the items.
![alt text](img/input-order.png)

![alt text](img/input-wallet.png)

**CWE ID**:
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

**Severity**: 6.5 (Medium) - Financial loss due to negative transactions allowed.

![alt text](img/input-score.png)

**Remediation**:
Implement proper input validation to ensure only positive quantities are allowed.
Perform server-side checks to validate the quantity before processing transactions.


## 10 - Improper Input Validation in File Upload Functionality

The file upload functionality in the complaint page is vulnerable to improper input validation. The front-end enforces a restriction on file size (maximum 100 KB) and allowed file extensions (`.pdf` and `.zip`). However, these restrictions can be bypassed by manipulating the file extension and size through intercepted requests.

- The interface does not allow files over 100 KB or with extensions other than `.pdf` or `.zip`.

    ![alt text](img/file-upload+100.png)

    ![alt text](img/file-upload-pdfziponly.png)


**Changing File Extension:**

- Upload a bash script `payload-script.sh` by changing its extension to `payload-script.sh.zip`.

    ![alt text](img/file-upload-script.png)

    ![alt text](img/file-upload-script-site.png)

**Manipulating Request with Burp Suite:**

- Intercept the upload request using Burp Suite.
- Modify the file extension back to `payload-script.sh` and insert additional data to bypass the 100 KB constraint.

Original Request:

![alt text](img/file-upload-request-original.png)

Altered Request:
        
![alt text](img/file-upload-request-altered.png)

The upload is successfully processed, allowing the malicious file to be uploaded.

**CWE ID**:
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

**Severity**: 9.8 (High) - Potential for arbitrary file uploads leading to remote code execution or further exploitation.

![alt text](img/file-upload-score.png)

**Remediation**:
Implement server-side validation to enforce file size and extension restrictions.

---
**Report by**: Pedro Coelho  

**Cesar School**  
**Specialization in Cybersecurity**  
**Web Application Security Course**  
**Instructor**: Petronio Lopes
