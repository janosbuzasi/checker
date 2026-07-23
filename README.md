# Checker

Simple HTTP / HTTPS / SSL / TLS website checker written in PHP.

## Current UI

The current interface matches the shared webtrash.ch styling:

- WT branding in the header
- burger-menu navigation
- consistent layout with the other tools

## Features

- HTTP / HTTPS availability checks
- redirect and response timing checks
- DNS hostname resolution
- direct public IPv4 and IPv6 targets
- reverse DNS lookups
- IP registration and abuse contact details via RDAP
- TLS and certificate inspection

## Notes

This is a lightweight shared-hosting-friendly tool with no database dependency.
Private, reserved, loopback, and link-local targets are blocked by default.
