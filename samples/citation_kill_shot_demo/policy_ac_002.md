# Policy-AC-002 v1.0: Remote Access Standard

**Owner:** ISSO
**Last reviewed:** 2026-01-08
**Next review:** 2026-07-08

## Purpose

Define requirements for remote access to systems within the CUI boundary.

## Policy

1. Remote access is permitted only through the Cisco AnyConnect VPN terminating
   at `vpn.hardseal.example`.
2. Split-tunneling is disabled.
3. Idle sessions terminate after 30 minutes of inactivity.
4. Session logs are forwarded to Splunk under the source
   `anyconnect_ra_session`.

## References

- Policy-AC-001 v2.0 (parent policy)
- NIST SP 800-171 r2 §3.1.12
