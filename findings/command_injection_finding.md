# OS Command Injection Vulnerability Report

## Vulnerability Details

**Type:** OS Command Injection  
**Target:** http://192.168.1.4/dvwa/vulnerabilities/exec/  
**Severity:** Critical

## Description

The application executes system commands using unsanitized user input passed to a system-level function.

## Proof of Concept

**Input supplied:**
```
127.0.0.1; whoami
```

**Result:**  
The application returned the output of the whoami command, showing execution as user 'www-data'.

## Impact

An attacker can execute arbitrary commands on the server, potentially leading to full system compromise, data theft, or service disruption.

## Remediation

Avoid passing user input directly to system calls. Use input validation, allow-lists, and safer APIs.
