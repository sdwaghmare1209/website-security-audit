# SQL Injection Vulnerability Report

## Vulnerability Details

**Type:** SQL Injection  
**Target:** http://192.168.1.4/dvwa/vulnerabilities/sqli/  
**Severity:** High

## Description

The application does not properly sanitize user input before using it in SQL queries.

## Proof of Concept

**Input used:**
```
1' OR '1'='1
```

**Result:**  
The application returned multiple database records, confirming SQL query manipulation.

## Impact

Attackers can access unauthorized database information, potentially exposing sensitive user data.

## Remediation

Use parameterized queries (prepared statements) and enforce strict input validation.
