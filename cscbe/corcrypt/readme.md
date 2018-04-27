# CorCrypt (70)

When you visit the website with Chrome, you get a "Not secure" warning.

Use SSLScan to scan the website for TLS vulnerabilities. It correctly identifies the HeartBleed flaw.

Use Metasploit (auxiliary/scanner/ssl/openssl_heartbleed, don't forget to set VERBOSE to true) to retrieve leaked data.

Within the leaked data there's a private key. Use this private key to decrypt the flag.
