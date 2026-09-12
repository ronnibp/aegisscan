# Security Policy

## Reporting a vulnerability

If you find a vulnerability in AegisScan itself, please open a private
[security advisory](https://github.com/ronnibp/aegisscan/security/advisories/new)
rather than a public issue. You'll get a response within a few days.

## Scope

- The AegisScan codebase and its dashboard server (`python -m aegisscan ui`)
- Note: the dashboard binds to `127.0.0.1` by design and is intended for local,
  single-user use. Do not expose it to untrusted networks.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
