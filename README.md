# Checker

Simple HTTP / HTTPS / SSL / TLS website checker written in PHP.

A lightweight web-based utility to quickly check website availability, connectivity, redirects, HTTP headers, TLS details, and SSL certificate health.

## Version

Current version:

v1.2.0

## Features

### Connectivity

- HTTP port 80 connectivity check
- HTTPS port 443 connectivity check
- response time measurement
- DNS hostname resolution
- public IP lookup

### HTTP / HTTPS

- HTTP status code detection
- HTTPS status code detection
- redirect location detection
- HTTP response header inspection
- HTTPS response header inspection

### SSL / TLS

- SSL certificate inspection
- certificate subject
- certificate issuer
- validity start date
- validity end date
- days remaining
- expiration warning
- SSL health badge
- TLS protocol detection
- TLS cipher detection
- cipher strength
- certificate serial
- SAN (Subject Alternative Names)

### API / UI

- clean dark responsive web UI
- JSON API endpoint
- copy JSON button
- raw JSON viewer
- version display
- modular code structure

## Supported Input

Examples:

```text
example.com
webtrash.ch
google.com
https://github.com
https://example.com/login
https://subdomain.example.com:443/path
