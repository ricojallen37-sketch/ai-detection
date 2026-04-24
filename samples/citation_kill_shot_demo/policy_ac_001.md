# Policy-AC-001 v2.0: Access Control Policy

**Owner:** CISO
**Last reviewed:** 2026-02-14
**Next review:** 2026-08-14

## Purpose

Define access-control requirements for systems processing or transmitting CUI
under the scope boundary defined in the Hardseal SSP.

## Scope

All systems within the CUI boundary. Specifically: the Okta tenant
`hardseal.okta.com`, the Splunk Cloud instance `hardseal.splunkcloud.com`, and
all endpoints managed by Intune under the tag `cui-boundary`.

## Policy

1. Access is granted on the principle of least privilege.
2. Privileged access requires MFA enforced by Okta with YubiKey 5 series
   hardware tokens (FIDO2/WebAuthn).
3. Shared accounts are prohibited except for break-glass scenarios documented
   under TKT-EMRG-101 through TKT-EMRG-199.
4. Account provisioning, modification, and revocation are logged to Splunk
   with a 365-day retention window (per AU-family policy).

## Enforcement

Violations are reported to the ISSO via `isso@hardseal.example`. The
ServiceNow form `INC-ACCESS-POLICY` is used for documented exceptions.

## References

- NIST SP 800-171 r2 §§3.1.1 through 3.1.22
- CMMC 2.0 Level 2 practices in the AC domain
