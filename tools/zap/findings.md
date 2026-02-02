# OWASP ZAP Active Scan Findings

## Scan Information

**Tool:** OWASP ZAP (Zed Attack Proxy) v2.17.0  
**Scan Type:** Active Security Scan  
**Target:** DVWA on Metasploitable2  
**Target URLs:**
- http://192.168.1.4
- https://192.168.1.4

**Scan Date:** February 1, 2026  
**Scan Time:** 15:01:18  
**Spider Coverage:** Complete application mapping  
**Active Scan:** Full vulnerability assessment

---

## Executive Summary

OWASP ZAP identified **29 security alerts** across multiple risk levels during the active scan of the DVWA application. The findings include critical remote code execution vulnerabilities, missing security controls, and various configuration weaknesses that expose the application to multiple attack vectors.

**Total Alerts:** 29  
**High Risk:** 2  
**Medium Risk:** 6  
**Low Risk:** 7  
**Informational:** 14

---

## Risk Distribution

### Alert Counts by Risk and Confidence

| Risk Level | User Confirmed | High | Medium | Low | **Total** |
|------------|----------------|------|--------|-----|-----------|
| **High** | 0 | 0 | 2 | 0 | **2 (6.9%)** |
| **Medium** | 0 | 1 | 4 | 1 | **6 (20.7%)** |
| **Low** | 0 | 2 | 5 | 0 | **7 (24.1%)** |
| **Informational** | 0 | 1 | 10 | 3 | **14 (48.3%)** |
| **Total** | 0 | 4 | 21 | 4 | **29 (100%)** |

---

## High Risk Findings

### 1. Remote Code Execution - CVE-2012-1823
**Risk Level:** High  
**Confidence:** Medium  
**CWE:** CWE-94 (Improper Control of Generation of Code)

**Description:**  
A critical remote code execution vulnerability exists in PHP-CGI based on CVE-2012-1823. This vulnerability allows an attacker to execute arbitrary PHP code remotely by passing specially crafted query strings that are interpreted as command-line arguments by the PHP CGI binary.

**Vulnerability Details:**
- **CVE:** CVE-2012-1823
- **Affected Component:** PHP-CGI (PHP versions < 5.3.12 and < 5.4.2)
- **Attack Vector:** Query string manipulation
- **CVSS Score:** 9.8 (Critical)

**Proof of Concept:**
```
GET /index.php?-s HTTP/1.1
Host: 192.168.1.4

Response: PHP source code disclosed
```

**Impact:**
- Complete remote code execution
- Full server compromise
- Data exfiltration capabilities
- Ability to install backdoors
- Lateral movement to other systems

**Affected URLs:**
- Multiple endpoints across the application
- Any PHP file accessible via CGI

**Remediation:**
1. **Immediate:** Upgrade PHP to version 5.3.12+ or 5.4.2+
2. Disable PHP-CGI if not required
3. Use PHP-FPM instead of CGI
4. Implement Web Application Firewall (WAF) rules
5. Apply vendor security patches

**References:**
- [CVE-2012-1823](https://nvd.nist.gov/vuln/detail/CVE-2012-1823)
- [PHP Security Advisory](https://www.php.net/archive/2012.php#id2012-05-03-1)

---

### 2. Source Code Disclosure - CVE-2012-1823
**Risk Level:** High  
**Confidence:** Medium  
**CWE:** CWE-541 (Inclusion of Sensitive Information in an Include File)

**Description:**  
Related to the RCE vulnerability, attackers can use CVE-2012-1823 to disclose PHP source code by using the -s parameter. This allows attackers to view the complete source code including database credentials, API keys, and business logic.

**Proof of Concept:**
```
GET /login.php?-s HTTP/1.1
Host: 192.168.1.4

Response: Complete PHP source code of login.php displayed
```

**Impact:**
- Complete source code disclosure
- Database credentials exposed
- API keys and secrets revealed
- Business logic understanding
- Facilitates further attacks

**Information Disclosed:**
- Database connection strings
- Authentication mechanisms
- Encryption keys and salts
- File paths and structure
- Third-party integrations

**Remediation:**
1. Upgrade PHP immediately (same as RCE finding)
2. Rotate all exposed credentials
3. Review code for hardcoded secrets
4. Implement proper secrets management
5. Use environment variables for sensitive data

**References:**
- [CVE-2012-1823](https://nvd.nist.gov/vuln/detail/CVE-2012-1823)

---

## Medium Risk Findings

### 3. Absence of Anti-CSRF Tokens
**Risk Level:** Medium  
**Confidence:** High  
**CWE:** CWE-352 (Cross-Site Request Forgery)

**Description:**  
No anti-CSRF tokens were found in HTML forms across the application. This allows attackers to craft malicious requests that will be executed by authenticated users, leading to unauthorized actions.

**Vulnerable Forms:**
- Login form
- Password change functionality
- User profile updates
- Administrative functions
- All state-changing operations

**Proof of Concept:**
```html
<!-- Malicious page hosted by attacker -->
<html>
<body onload="document.forms[0].submit()">
<form action="http://192.168.1.4/dvwa/vulnerabilities/csrf/" method="GET">
  <input type="hidden" name="password_new" value="hacked123">
  <input type="hidden" name="password_conf" value="hacked123">
  <input type="hidden" name="Change" value="Change">
</form>
</body>
</html>
```

**Impact:**
- Password changes without user consent
- Unauthorized transactions
- Account modifications
- Data manipulation
- Administrative actions performed by attacker

**Affected URLs:**
- `/dvwa/vulnerabilities/csrf/`
- `/dvwa/vulnerabilities/upload/`
- `/dvwa/login.php`
- Multiple state-changing endpoints

**Remediation:**
1. Implement anti-CSRF tokens (Synchronizer Token Pattern)
2. Use framework-provided CSRF protection
3. Validate tokens on server-side
4. Implement SameSite cookie attribute
5. Require re-authentication for sensitive operations

**Example Implementation (PHP):**
```php
// Generate token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// In form
<input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

// Validate
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('CSRF token validation failed');
}
```

**References:**
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

### 4. Content Security Policy (CSP) Header Not Set
**Risk Level:** Medium  
**Confidence:** Medium  
**CWE:** CWE-693 (Protection Mechanism Failure)

**Description:**  
Content Security Policy (CSP) header is not implemented, leaving the application vulnerable to XSS attacks, clickjacking, and other code injection attacks.

**Missing Header:**
```
Content-Security-Policy: default-src 'self'
```

**Impact:**
- Reduced XSS protection
- Inline JavaScript execution allowed
- External resource loading unrestricted
- Data exfiltration easier
- Limited defense-in-depth

**Affected URLs:**
- All application pages
- Global header configuration missing

**Remediation:**

**Basic CSP Implementation:**
```apache
# Apache configuration
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
```

**PHP Implementation:**
```php
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'");
```

**Recommended CSP Directives:**
- `default-src 'self'` - Only load resources from same origin
- `script-src 'self'` - Only execute scripts from same origin
- `object-src 'none'` - Disable plugins
- `frame-ancestors 'none'` - Prevent clickjacking
- `upgrade-insecure-requests` - Force HTTPS

**References:**
- [MDN - Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

---

### 5. Directory Browsing
**Risk Level:** Medium  
**Confidence:** Medium  
**CWE:** CWE-548 (Directory Listing)

**Description:**  
Directory browsing/listing is enabled on the web server, allowing attackers to view the contents of directories and discover files that should remain hidden.

**Exposed Directories:**
- `/dvwa/hackable/uploads/`
- `/dvwa/docs/`
- `/dvwa/external/`
- Various application directories

**Proof of Concept:**
```
GET /dvwa/hackable/uploads/ HTTP/1.1
Host: 192.168.1.4

Response: Directory listing showing all uploaded files
```

**Impact:**
- File structure disclosure
- Discovery of backup files
- Access to uploaded files
- Configuration file discovery
- Sensitive document exposure

**Information Disclosed:**
- File names and extensions
- Directory structure
- Last modification dates
- File sizes
- Hidden files and backups

**Remediation:**

**Apache:**
```apache
# In .htaccess or httpd.conf
Options -Indexes

# Or for specific directory
<Directory /var/www/html/dvwa/hackable/uploads>
    Options -Indexes
</Directory>
```

**Nginx:**
```nginx
location /dvwa/hackable/uploads/ {
    autoindex off;
}
```

**Verification:**
```bash
curl http://192.168.1.4/dvwa/hackable/uploads/
# Should return 403 Forbidden or custom error page
```

---

### 6. HTTP Only Site (Missing HTTPS)
**Risk Level:** Medium  
**Confidence:** Medium  
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)

**Description:**  
The entire site is served over HTTP without HTTPS/TLS encryption. All data transmitted between the client and server is in cleartext and can be intercepted.

**Impact:**
- Session hijacking via network sniffing
- Credentials transmitted in cleartext
- Man-in-the-middle attacks
- Cookie theft
- Data tampering
- Eavesdropping on sensitive information

**Data at Risk:**
- Login credentials
- Session tokens
- Personal information
- Database queries
- API communications

**Remediation:**

1. **Obtain SSL/TLS Certificate:**
   - Let's Encrypt (free)
   - Commercial CA certificate
   - Self-signed for testing only

2. **Configure HTTPS:**
```apache
# Apache SSL Configuration
<VirtualHost *:443>
    ServerName dvwa.local
    DocumentRoot /var/www/html/dvwa
    
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>

# Redirect HTTP to HTTPS
<VirtualHost *:80>
    ServerName dvwa.local
    Redirect permanent / https://dvwa.local/
</VirtualHost>
```

3. **Implement HSTS:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**References:**
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

---

### 7. Missing Anti-clickjacking Header
**Risk Level:** Medium  
**Confidence:** Medium  
**CWE:** CWE-1021 (Improper Restriction of Rendered UI Layers)

**Description:**  
X-Frame-Options header is not set, allowing the application to be embedded in frames/iframes, making it vulnerable to clickjacking attacks.

**Missing Header:**
```
X-Frame-Options: DENY
```

**Proof of Concept:**
```html
<!-- Attacker's malicious page -->
<html>
<head><title>Win a Prize!</title></head>
<body>
<h1>Click here to win!</h1>
<iframe src="http://192.168.1.4/dvwa/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" 
        style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%">
</iframe>
</body>
</html>
```

**Impact:**
- Clickjacking attacks
- UI redress attacks
- Tricking users into unwanted actions
- Password changes
- Unauthorized transactions

**Remediation:**

**Apache:**
```apache
Header always set X-Frame-Options "DENY"
# or for same-origin framing
Header always set X-Frame-Options "SAMEORIGIN"
```

**PHP:**
```php
header('X-Frame-Options: DENY');
```

**Modern Alternative (CSP):**
```
Content-Security-Policy: frame-ancestors 'none';
```

**References:**
- [MDN - X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [OWASP Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

---

### 8. Vulnerable JavaScript Library
**Risk Level:** Medium  
**Confidence:** Medium  
**CWE:** CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

**Description:**  
The application uses outdated JavaScript libraries with known security vulnerabilities.

**Vulnerable Libraries Detected:**
- **jQuery 1.x** - Multiple CVEs
  - CVE-2019-11358 (Prototype Pollution)
  - CVE-2020-11022 (XSS vulnerability)
  - CVE-2020-11023 (XSS vulnerability)
  - CVE-2020-7656 (Prototype Pollution)

**Affected Versions:**
```
jquery-1.x.x.min.js (detected)
Current safe version: jQuery 3.7.0+
```

**Impact:**
- Cross-Site Scripting (XSS)
- Prototype pollution attacks
- Client-side code execution
- DOM manipulation vulnerabilities

**Remediation:**

1. **Update jQuery:**
```html
<!-- Replace old version -->
<script src="jquery-1.x.x.min.js"></script>

<!-- With current version -->
<script src="https://code.jquery.com/jquery-3.7.1.min.js" 
        integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo=" 
        crossorigin="anonymous"></script>
```

2. **Use Subresource Integrity (SRI):**
```html
<script src="https://code.jquery.com/jquery-3.7.1.min.js" 
        integrity="sha256-xxxxx" 
        crossorigin="anonymous"></script>
```

3. **Audit Dependencies:**
```bash
npm audit
npm update jquery
```

**References:**
- [jQuery Security Advisories](https://github.com/jquery/jquery/security/advisories)
- [Snyk Vulnerability Database](https://security.snyk.io/package/npm/jquery)

---

## Low Risk Findings

### 9. Cookie No HttpOnly Flag
**Risk Level:** Low  
**Confidence:** High  
**CWE:** CWE-1004 (Sensitive Cookie Without 'HttpOnly' Flag)

**Description:**  
Session cookies are set without the HttpOnly flag, making them accessible to JavaScript and vulnerable to XSS-based theft.

**Affected Cookies:**
- `PHPSESSID`
- `security` (DVWA security level)

**Current Cookie:**
```
Set-Cookie: PHPSESSID=abc123; path=/
```

**Impact:**
- Session hijacking via XSS
- Cookie theft through JavaScript
- Increased impact of XSS vulnerabilities

**Remediation:**

**PHP Configuration:**
```php
// In php.ini
session.cookie_httponly = 1
session.cookie_secure = 1

// Or in code
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);
```

**Apache:**
```apache
Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure;SameSite=Strict
```

---

### 10. Cookie without SameSite Attribute
**Risk Level:** Low  
**Confidence:** Medium  
**CWE:** CWE-1275 (Sensitive Cookie with Improper SameSite Attribute)

**Description:**  
Cookies do not include the SameSite attribute, making them vulnerable to CSRF attacks.

**Recommended Cookie:**
```
Set-Cookie: PHPSESSID=abc123; path=/; HttpOnly; Secure; SameSite=Strict
```

**SameSite Options:**
- **Strict:** Cookie only sent with same-site requests
- **Lax:** Cookie sent with top-level navigation
- **None:** Cookie sent with all requests (requires Secure)

**Remediation:**
```php
session_set_cookie_params([
    'samesite' => 'Strict'
]);
```

---

### 11. In Page Banner Information Leak
**Risk Level:** Low  
**Confidence:** Medium  
**CWE:** CWE-200 (Information Exposure)

**Description:**  
The application displays server version information in page content and banners.

**Information Disclosed:**
- "Powered by PHP/5.2.4"
- Server software versions
- Framework information

**Remediation:**
- Remove version information from page footers
- Disable server banners
- Customize error pages

---

### 12. Information Disclosure - Debug Error Messages
**Risk Level:** Low  
**Confidence:** Medium  
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

**Description:**  
Detailed error messages are displayed to users, revealing file paths, database information, and application structure.

**Example Error:**
```
Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource in /var/www/dvwa/vulnerabilities/sqli/index.php on line 42
```

**Information Disclosed:**
- Full file paths
- Database errors
- Function names
- Line numbers

**Remediation:**

**PHP Configuration:**
```ini
; php.ini
display_errors = Off
log_errors = On
error_reporting = E_ALL
error_log = /var/log/php_errors.log
```

**Custom Error Handler:**
```php
error_reporting(0);
ini_set('display_errors', 0);
set_error_handler('customErrorHandler');
```

---

### 13. Server Leaks Information via "X-Powered-By" Header
**Risk Level:** Low  
**Confidence:** Medium  
**CWE:** CWE-200 (Information Exposure)

**Description:**  
X-Powered-By header reveals PHP version information.

**Current Header:**
```
X-Powered-By: PHP/5.2.4-2ubuntu5.10
```

**Remediation:**

**PHP:**
```ini
; php.ini
expose_php = Off
```

**Apache:**
```apache
Header unset X-Powered-By
Header always unset X-Powered-By
```

---

### 14. Server Leaks Version Information via "Server" Header
**Risk Level:** Low  
**Confidence:** Medium  
**CWE:** CWE-200 (Information Exposure)

**Description:**  
Server header reveals Apache version information.

**Current Header:**
```
Server: Apache/2.2.8 (Ubuntu)
```

**Remediation:**

**Apache:**
```apache
ServerTokens Prod
ServerSignature Off
```

**Result:**
```
Server: Apache
```

---

### 15. X-Content-Type-Options Header Missing
**Risk Level:** Low  
**Confidence:** Medium  
**CWE:** CWE-693 (Protection Mechanism Failure)

**Description:**  
X-Content-Type-Options header is not set, allowing MIME-sniffing attacks.

**Remediation:**
```apache
Header always set X-Content-Type-Options "nosniff"
```

---

## Informational Findings

### 16. Authentication Request Identified
**Risk Level:** Informational  
**Confidence:** Medium

**Description:**  
Authentication endpoints identified for potential brute-force testing.

**Endpoints:**
- `/dvwa/login.php`
- POST parameters: username, password

**Note:** Ensure rate limiting and account lockout mechanisms are in place.

---

## Summary Statistics

### Vulnerability Distribution by Category

| Category | Count |
|----------|-------|
| Code Execution | 2 |
| Missing Security Controls | 8 |
| Information Disclosure | 6 |
| Configuration Issues | 5 |
| Outdated Components | 1 |
| Cookie Security | 2 |
| Authentication | 1 |
| Informational | 4 |

### CVE References

- **CVE-2012-1823** - PHP CGI Remote Code Execution (Critical)
- **CVE-2019-11358** - jQuery Prototype Pollution
- **CVE-2020-11022** - jQuery XSS Vulnerability
- **CVE-2020-11023** - jQuery XSS Vulnerability
- **CVE-2020-7656** - jQuery Prototype Pollution

---

## Remediation Priority

### Critical Priority (Immediate - 24 hours)
1. ✅ Upgrade PHP to version 5.3.12+ or 5.4.2+ (addresses CVE-2012-1823)
2. ✅ Review and rotate any exposed credentials from source code disclosure
3. ✅ Disable PHP-CGI or migrate to PHP-FPM

### High Priority (1 week)
4. ✅ Implement anti-CSRF tokens across all forms
5. ✅ Update jQuery to version 3.7.0+
6. ✅ Disable directory browsing/listing
7. ✅ Implement HTTPS with valid SSL certificate

### Medium Priority (2 weeks)
8. ✅ Implement Content Security Policy (CSP) headers
9. ✅ Add X-Frame-Options header
10. ✅ Configure secure cookie attributes (HttpOnly, Secure, SameSite)
11. ✅ Remove server version information
12. ✅ Disable debug error messages in production

---

## Recommended Security Headers Configuration

```apache
# /etc/apache2/conf-available/security.conf

# Server information
ServerTokens Prod
ServerSignature Off

# Security Headers
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Content Security Policy
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"

# HSTS (only use with valid HTTPS)
# Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# Remove server information
Header unset X-Powered-By
Header always unset X-Powered-By

# Directory browsing
Options -Indexes

# Cookie security
Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure;SameSite=Strict
```

---

## Validation Commands

### Check Security Headers
```bash
curl -I http://192.168.1.4/ | grep -E "(X-Frame|X-Content|CSP|HSTS)"
```

### Test for Directory Browsing
```bash
curl http://192.168.1.4/dvwa/hackable/uploads/
```

### Verify PHP Version
```bash
curl -I http://192.168.1.4/ | grep X-Powered-By
```

### Test CSRF Protection
```bash
# Check for CSRF tokens in forms
curl http://192.168.1.4/dvwa/login.php | grep csrf
```

---

## References

- [OWASP ZAP User Guide](https://www.zaproxy.org/docs/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CVE Database](https://cve.mitre.org/)
- [NIST NVD](https://nvd.nist.gov/)
- [Mozilla Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)

---

## Next Steps

1. **Immediate Actions:**
   - Address critical RCE vulnerability
   - Upgrade PHP and apply security patches
   - Implement CSRF protection

2. **Short-term:**
   - Configure all security headers
   - Update JavaScript libraries
   - Enable HTTPS

3. **Ongoing:**
   - Regular security scanning
   - Dependency updates
   - Security training for developers
   - Implement CI/CD security testing

4. **Re-scan:**
   - Run ZAP scan after remediation
   - Verify all fixes are effective
   - Document remaining risks

---

**Scan completed:** February 1, 2026, 15:01:18  
**Report generated:** February 1, 2026  
**Auditor:** Sumit  
**ZAP Version:** 2.17.0
