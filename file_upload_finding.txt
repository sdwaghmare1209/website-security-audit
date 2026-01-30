Vulnerability: Insecure File Upload (Remote Code Execution)
Target: http://192.168.1.4/dvwa/vulnerabilities/upload/
Severity: Critical

Description:
The application allows unrestricted file uploads and executes uploaded files from a web-accessible directory.

Proof of Concept:
A PHP file named test.php was uploaded and accessed.

URL:
http://192.168.1.4/dvwa/hackable/uploads/test.php

Result:
The server executed the uploaded PHP file.

Impact:
Attackers can execute arbitrary code on the server, potentially leading to full system compromise.

Remediation:
Implement strict file type validation, rename uploaded files, store uploads outside web root, and disable script execution in upload directories.
