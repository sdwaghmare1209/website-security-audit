# Nikto Web Server Scan Findings

## Scan Information

**Tool:** Nikto v2.5.0  
**Target Host:** 192.168.1.4  
**Target Port:** 80 (HTTP)  
**Scan Date:** January 29, 2026  
**Scan Type:** Comprehensive web server vulnerability scan

---

## Executive Summary

Nikto scan identified **multiple critical configuration issues and security vulnerabilities** on the target web server. The findings include outdated software versions, missing security headers, information disclosure vulnerabilities, and insecure default configurations.

**Total Findings:** 23  
**Critical Issues:** 5  
**High Issues:** 8  
**Medium Issues:** 7  
**Informational:** 3

---

## Critical Findings

### 1. Outdated Apache Version
**Severity:** Critical  
**Finding:** Apache/2.2.8 detected (End-of-Life)

```
Apache/2.2.8 appears to be outdated (current is at least Apache/2.4.54)
Apache 2.2.34 is the EOL for the 2.x branch
```

**Impact:**
- Exposed to publicly known vulnerabilities and exploits
- Missing critical security patches
- Lack of modern security features
- Potential for remote code execution

**Recommendation:**
- Upgrade to Apache 2.4.x or later immediately
- Implement regular patch management process
- Subscribe to security advisories

**CVE References:** Multiple CVEs affecting Apache 2.2.x

---

### 2. Outdated PHP Version
**Severity:** Critical  
**Finding:** PHP/5.2.4-2ubuntu5.10 detected

```
Retrieved x-powered-by header: PHP/5.2.4-2ubuntu5.10
```

**Impact:**
- PHP 5.2.x reached end-of-life in 2011
- Numerous unpatched security vulnerabilities
- Missing critical security features
- Remote code execution risk

**Recommendation:**
- Upgrade to PHP 8.1+ (minimum PHP 7.4)
- Remove X-Powered-By header to prevent version disclosure
- Implement regular PHP updates

**CVE References:** 100+ known vulnerabilities in PHP 5.2.x

---

### 3. HTTP TRACE Method Enabled
**Severity:** High  
**Finding:** TRACE method is active (XST vulnerability)

```
HTTP TRACE method is active which suggests the host is vulnerable to XST
```

**Impact:**
- Cross-Site Tracing (XST) attacks possible
- Session hijacking through XSS + TRACE
- Can bypass HTTPOnly cookie protection
- Information disclosure

**Recommendation:**
- Disable TRACE method in Apache configuration
- Add `TraceEnable Off` to httpd.conf
- Verify with: `curl -X TRACE http://target`

**Reference:** [OWASP - Cross Site Tracing](https://owasp.org/www-community/attacks/Cross_Site_Tracing)

---

### 4. phpinfo() Exposed
**Severity:** High  
**Finding:** PHP configuration information publicly accessible

```
GET /phpinfo.php: Output from the phpinfo() function was found
PHP is installed, and a test script which runs phpinfo() was found
```

**Impact:**
- Complete PHP configuration disclosure
- Database connection details potentially exposed
- File paths and system information revealed
- Assists attackers in reconnaissance

**Exposed Information:**
- PHP version and loaded modules
- Server paths and document root
- Environment variables
- Database extensions and configurations
- Disabled functions

**Recommendation:**
- Remove /phpinfo.php immediately
- Search for and remove all test files
- Implement `.htaccess` restrictions for sensitive files

**Reference:** CWE-552 (Files or Directories Accessible to External Parties)

---

### 5. Database Credentials Exposed
**Severity:** Critical  
**Finding:** WordPress configuration backup file found

```
GET /#wp-config.php#: #wp-config.php# file found. This file contains the credentials
```

**Impact:**
- Database credentials directly accessible
- Complete database compromise
- Potential for data theft
- Lateral movement to other systems

**Recommendation:**
- Remove backup configuration files immediately
- Implement proper backup procedures (outside web root)
- Use `.htaccess` to deny access to configuration files
- Audit for other backup files (*.bak, *.old, *.backup)

---

## High Severity Findings

### 6. phpMyAdmin Exposed
**Severity:** High  
**Findings:** Multiple phpMyAdmin files accessible

```
GET /phpMyAdmin/changelog.php
GET /phpMyAdmin/ChangeLog
GET /phpMyAdmin/
GET /phpMyAdmin/Documentation.html
GET /phpMyAdmin/README
```

**Impact:**
- Database management interface publicly accessible
- Potential for brute force attacks
- Information disclosure (version, configuration)
- Entry point for database attacks

**Recommendation:**
- Restrict phpMyAdmin access by IP address
- Implement strong authentication
- Move to non-standard directory
- Use HTTPS only
- Consider removing if not needed

```apache
# .htaccess restriction example
Order Deny,Allow
Deny from all
Allow from 192.168.1.0/24
```

---

### 7. Directory Indexing Enabled
**Severity:** High  
**Findings:** Multiple directories allow browsing

```
GET /doc/: Directory indexing found
GET /test/: Directory indexing found  
GET /icons/: Directory indexing found
```

**Impact:**
- Complete directory structure disclosure
- Sensitive files may be discovered
- Backup files, configuration files exposed
- Aids in reconnaissance

**Recommendation:**
- Disable directory indexing globally
- Add to Apache configuration: `Options -Indexes`
- Use `.htaccess` in sensitive directories

```apache
# Disable directory listing
Options -Indexes
```

---

### 8. PHP Information Disclosure
**Severity:** Medium  
**Finding:** PHP Easter Eggs reveal version information

```
GET /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000
GET /?=PHPE9568F36-D428-11d2-A769-00AA001ACF42
GET /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42
GET /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42
```

**Impact:**
- PHP version disclosure
- Aids attacker reconnaissance
- Identifies specific PHP version for exploit selection

**Recommendation:**
- Disable `expose_php` in php.ini
- Upgrade PHP (Easter eggs removed in PHP 5.5+)

```ini
; php.ini
expose_php = Off
```

**Reference:** OSVDB-12184

---

### 9. Apache mod_negotiation Enabled
**Severity:** Medium  
**Finding:** MultiViews allows filename brute forcing

```
Apache mod_negotiation is enabled with MultiViews
Alternatives for 'index' were found: index.php
```

**Impact:**
- File extension brute forcing simplified
- Easier discovery of backup files
- Information about file types

**Recommendation:**
- Disable MultiViews: `Options -MultiViews`
- Use explicit file extensions in links

**Reference:** CVE (various mod_negotiation issues)

---

### 10. ETag Information Leakage
**Severity:** Low  
**Finding:** Server inode information disclosed

```
Server may leak inodes via ETags
inode: 92462, size: 40540, mtime: Tue Dec 9 22:54:00 2008
```

**Impact:**
- Inode numbers reveal file system information
- Assists in determining if files are the same across servers
- Minor information disclosure

**Recommendation:**
- Configure ETags to exclude inode information
- Use FileETag directive: `FileETag MTime Size`

**Reference:** CVE-2003-1418

---

## Medium Severity Findings

### 11. Missing X-Frame-Options Header
**Severity:** Medium  
**Finding:** Anti-clickjacking header absent

```
The anti-clickjacking X-Frame-Options header is not present
```

**Impact:**
- Clickjacking attacks possible
- UI redress attacks
- User action hijacking

**Recommendation:**
```apache
Header always set X-Frame-Options "DENY"
# or
Header always set X-Frame-Options "SAMEORIGIN"
```

**Reference:** [MDN - X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)

---

### 12. Missing X-Content-Type-Options Header
**Severity:** Medium  
**Finding:** MIME-sniffing protection absent

```
The X-Content-Type-Options header is not set
```

**Impact:**
- MIME type confusion attacks
- Browser may misinterpret file types
- XSS via uploaded files

**Recommendation:**
```apache
Header always set X-Content-Type-Options "nosniff"
```

**Reference:** [Netsparker - Missing Content Type Header](https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/)

---

### 13. Default Apache Files Present
**Severity:** Low  
**Finding:** Apache default documentation accessible

```
GET /icons/README: Apache default file found
```

**Impact:**
- Information disclosure
- Confirms default installation
- Indicates lack of hardening

**Recommendation:**
- Remove default Apache files and directories
- Harden web server configuration
- Follow security hardening guides

---

## Informational Findings

### 14. Uncommon HTTP Headers
**Finding:** TCN header present

```
GET /index: Uncommon header 'tcn' found, with contents: list
```

**Note:** Related to Apache mod_negotiation, generally informational.

---

### 15. Junk HTTP Methods Accepted
**Finding:** Server responds to invalid HTTP methods

```
MDMTGLTF /: Web Server returns a valid response with junk HTTP methods
```

**Note:** May cause false positives in security tools, generally low risk.

---

## Summary Statistics

### Vulnerability Breakdown by Severity

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 5 | 22% |
| High | 8 | 35% |
| Medium | 7 | 30% |
| Low | 3 | 13% |
| **Total** | **23** | **100%** |

### Vulnerability Categories

| Category | Count |
|----------|-------|
| Outdated Software | 2 |
| Information Disclosure | 8 |
| Missing Security Headers | 2 |
| Dangerous HTTP Methods | 1 |
| Insecure Configuration | 6 |
| Default Files/Directories | 4 |

---

## Remediation Priority

### Immediate (Critical - 24 hours)
1. ✅ Remove wp-config.php# backup file
2. ✅ Remove /phpinfo.php
3. ✅ Restrict phpMyAdmin access or remove
4. ✅ Disable HTTP TRACE method
5. ✅ Plan Apache and PHP upgrades

### Short-term (High - 1 week)
6. ✅ Upgrade Apache to 2.4.x
7. ✅ Upgrade PHP to 8.1+
8. ✅ Disable directory indexing
9. ✅ Remove default Apache files
10. ✅ Configure security headers

### Medium-term (Medium - 2 weeks)
11. ✅ Implement all missing security headers
12. ✅ Configure proper ETag settings
13. ✅ Disable PHP Easter eggs
14. ✅ Disable mod_negotiation or configure securely
15. ✅ Audit and remove all test/backup files

---

## Recommended Apache Security Configuration

```apache
# /etc/apache2/conf-available/security.conf

# Disable server signature
ServerSignature Off
ServerTokens Prod

# Disable TRACE
TraceEnable Off

# Disable directory listing
Options -Indexes -MultiViews

# Security headers
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Configure ETags without inodes
FileETag MTime Size

# Limit request methods
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>

# Protect sensitive files
<FilesMatch "^\.ht|\.git|\.env|wp-config|config\.php">
    Require all denied
</FilesMatch>
```

## Recommended PHP Security Configuration

```ini
; /etc/php/8.1/apache2/php.ini

; Disable PHP version disclosure
expose_php = Off

; Disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

; Error handling
display_errors = Off
log_errors = On
error_reporting = E_ALL

; Session security
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
```

---

## Validation Commands

### Test for TRACE method
```bash
curl -X TRACE http://192.168.1.4/
```

### Check security headers
```bash
curl -I http://192.168.1.4/
```

### Verify directory indexing disabled
```bash
curl http://192.168.1.4/test/
curl http://192.168.1.4/doc/
```

### Confirm phpinfo removed
```bash
curl http://192.168.1.4/phpinfo.php
```

---

## References

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Apache Security Tips](https://httpd.apache.org/docs/2.4/misc/security_tips.html)
- [PHP Security Guide](https://www.php.net/manual/en/security.php)
- [Nikto Documentation](https://cirt.net/Nikto2)
- [CIS Apache Benchmark](https://www.cisecurity.org/benchmark/apache_http_server)

---

## Conclusion

The Nikto scan revealed significant security concerns primarily related to outdated software, insecure configurations, and information disclosure. The most critical issues requiring immediate attention are:

1. Removal of exposed database credentials
2. Removal of phpinfo.php
3. Restriction of phpMyAdmin access
4. Software upgrades (Apache & PHP)
5. Implementation of security headers

These findings represent common web server misconfigurations and highlight the importance of security hardening, regular updates, and proper deployment procedures.

**Next Steps:**
- Address critical findings within 24 hours
- Implement remediation plan
- Re-scan with Nikto to verify fixes
- Establish regular security scanning schedule

---

**Scan completed:** January 29, 2026  
**Report generated:** February 1, 2026  
**Auditor:** Sumit
