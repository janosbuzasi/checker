# Checker

Simple HTTP / HTTPS / SSL / TLS website checker written in PHP.

A lightweight web-based tool to quickly check website availability, connectivity, and SSL certificate health.

## Features

- HTTP connectivity check (port 80)
- HTTPS connectivity check (port 443)
- HTTP status code detection
- HTTPS status code detection
- DNS hostname resolution
- Public IP lookup
- SSL certificate inspection
- Certificate issuer information
- Certificate validity dates
- Expiration warning (days remaining)
- JSON API endpoint
- Clean dark web UI
- Input normalization

## Supported Input

Examples:

example.com
webtrash.ch
google.com
https://github.com
https://example.com/login
https://subdomain.example.com:443/path

The checker automatically extracts and normalizes the hostname.

## Example URLs

Web UI:

https://yourdomain.com/checker/index.php

Check a target:

https://yourdomain.com/checker/index.php?host=webtrash.ch

JSON API:

https://yourdomain.com/checker/index.php?host=webtrash.ch&format=json

## Example JSON Response

```json
{
  "input": "webtrash.ch",
  "host": "webtrash.ch",
  "checked_at": "2026-05-12T18:00:00+00:00",
  "ips": [
    "104.21.55.123"
  ],
  "http": {
    "open": true,
    "response_ms": 42
  },
  "https": {
    "open": true,
    "response_ms": 51
  },
  "http_status": {
    "status_code": 301
  },
  "https_status": {
    "status_code": 200
  },
  "ssl": {
    "subject": "webtrash.ch",
    "issuer": "Let's Encrypt",
    "valid_from": "2026-04-01 00:00:00",
    "valid_to": "2026-06-30 23:59:59",
    "days_left": 49,
    "expired": false
  }
}
