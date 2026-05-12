# Checker

Simple HTTP / HTTPS / SSL / TLS website checker written in PHP.

Features:
- DNS lookup
- Public IP resolve
- HTTP port check
- HTTPS port check
- HTTP/HTTPS status code
- SSL certificate inspection
- Expiration warning
- JSON API endpoint

Example:
https://yourdomain.com/checker/index.php?host=example.com

JSON API:
https://yourdomain.com/checker/index.php?host=example.com&format=json

Security:
- Blocks localhost/private IP targets
- Input validation
- Connection timeout limits

Requirements:
- PHP 8+
- OpenSSL enabled
- dns_get_record support
