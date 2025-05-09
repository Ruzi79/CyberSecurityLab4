1. Basic vulnerability scan using Nessus
   
I performed a basic vulnerability scan using Nessus, targeting the vulnerable machine with IP address 192.168.56.102.The scan completed successfully and identified multiple vulnerabilities with varying severity levels.

![image](https://github.com/user-attachments/assets/61e44df5-e87d-4700-ad0a-0cce48852d2f)

2. Analyze scan results
   
a. Review detected vulnerabilities by severity

According to the Nessus scan results, the vulnerabilities are categorized as follows:

Critical:10    High:6    Medium:24

![image](https://github.com/user-attachments/assets/88ea432c-b7fd-4057-99c7-aa53a13389a3)

b. Click on a few vulnerabilities to view:

I reviewed several detected vulnerabilities in detail. Here are some examples:

1)SSL DROWN Attack Vulnerability (Decrypting RSA with Obsolete and Weakened eNcryption)

Description: The remote host supports SSLv2 and therefore may be affected by a vulnerability that allows a cross-protocol Bleichenbacher padding oracle attack known as DROWN (Decrypting RSA with Obsolete and Weakened eNcryption). This vulnerability exists due to a flaw in the Secure Sockets Layer Version 2 (SSLv2) implementation, and it allows captured TLS traffic to be decrypted. A man-in-the-middle attacker can exploit this to decrypt the TLS connection by utilizing previously captured traffic and weak cryptography along with a series of specially crafted connections to an SSLv2 server that uses the same private key.

CVE ID: CVE-2016-0800

Exploitability: Exploit Available: false. There is currently no known public exploit available for this vulnerability. Although it may pose a risk, exploitation is unlikely without advanced knowledge or internal access.

Suggested fixes: Disable SSLv2 and export grade cryptography cipher suites. Ensure that private keys are not used anywhere with server software that supports SSLv2 connections.

![image](https://github.com/user-attachments/assets/17f7deab-6fb6-4b2d-af59-5ee335c5cc00)

2)Apache Tomcat AJP Connector Request Injection (Ghostcat)

Description:A file read/inclusion vulnerability was found in AJP connector. A remote, unauthenticated attacker could exploit this vulnerability to read web application files from a vulnerable server. In instances where the vulnerable server allows file uploads, an attacker could upload malicious JavaServer Pages (JSP) code within a variety of file types and gain remote code execution (RCE).

CVE ID: CVE-2020-1745

Exploitability: Exploit Available: true. This vulnerability is publicly known and can be exploited using tools or custom scripts. Attackers can use it to compromise the system remotely without needing special privileges.

Suggested fixes:Update the AJP configuration to require authorization and/or upgrade the Tomcat server to 7.0.100, 8.5.51, 9.0.31 or later.

![image](https://github.com/user-attachments/assets/47382078-340f-469f-9d22-02b68b562954)

3)SSL Anonymous Cipher Suites Supported

Description:The remote host supports the use of anonymous SSL ciphers. While this enables an administrator to set up a service that encrypts traffic without having to generate and configure SSL certificates, it offers no way to verify the remote host's identity and renders the service vulnerable to a man-in-the-middle attack.

CVE ID: CVE-2007-1858

Exploitability: Exploit Available: false. There is currently no known public exploit available for this vulnerability. Although it may pose a risk, exploitation is unlikely without advanced knowledge or internal access.

Suggested fixes: Reconfigure the affected application if possible to avoid use of weak ciphers.

![image](https://github.com/user-attachments/assets/ea71bde2-0489-4596-a6a8-ed24d4268c4d)

3. Repeat with OpenVAS

   ![image](https://github.com/user-attachments/assets/29767ead-5c46-4dc8-b9fb-2cd091a7c7c6)


I repeated the vulnerability assessment using OpenVAS.The scan detected the following vulnerabilities by severity:

Low:6    High:21    Medium:40

![image](https://github.com/user-attachments/assets/778bcd9a-5968-4682-8dd7-05addded051e)


I also examined some vulnerabilities found by OpenVAS:

1)TWiki XSS and Command Execution Vulnerabilities

Description: TWiki is prone to Cross-Site Scripting (XSS) and Command Execution Vulnerabilities.

CVE ID:CVE-2008-5304

Exploitability: Exploit Available: True. This vulnerability is publicly known and can be exploited using tools or custom scripts. Attackers can use it to compromise the system remotely without needing special privileges.

Suggested fixes: Upgrade to version 4.2.4 or later.

![image](https://github.com/user-attachments/assets/4d6d1947-f815-48d3-8d72-474c1059c66c)

2)phpMyAdmin 'error.php' Cross Site Scripting Vulnerability

Description: phpMyAdmin is prone to a cross-site scripting (XSS) vulnerability.

CVE ID:CVE-2010-4480

Exploitability: Exploit Available: True. This vulnerability is publicly known and can be exploited using tools or custom scripts. Attackers can use it to compromise the system remotely without needing special privileges.

Suggested fixes: No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer 
release, disable respective features, remove the product or replace the product by another one.

![image](https://github.com/user-attachments/assets/a66e024f-6f2c-4c2d-a571-0bd8335d670f)

In conclusion, the vulnerability scans conducted using Nessus and OpenVAS successfully identified multiple security issues on the target machine.
