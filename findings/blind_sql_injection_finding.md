# Blind SQL Injection Vulnerability Report

## Vulnerability Details

**Type:** Blind SQL Injection  
**Target:** http://192.168.1.4/dvwa/vulnerabilities/sqli_blind/  
**Severity:** High

## Description

The application allows blind SQL injection through unsanitized user input, enabling attackers to manipulate SQL query logic using boolean-based conditions.

## Proof of Concept

**TRUE:**
```
1' AND '1'='1 → User exists
```

**FALSE:**
```
1' AND '1'='2 → User missing
```

## Impact

Attackers can infer and extract database information without visible error messages or output.

## Remediation

Use prepared statements and parameterized queries. Validate and sanitize all user input.
