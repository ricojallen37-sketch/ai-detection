# Procedure-MFA-003 v1.0: MFA Enrollment Procedure

**Owner:** Help Desk Lead
**Last reviewed:** 2026-03-01

## Steps

1. New user receives enrollment email from `okta@hardseal.example` within 24 hours
   of HR onboarding completion.
2. User clicks enrollment link and authenticates with temporary passcode issued
   by the ISSO via Secure Share.
3. User registers YubiKey 5 series token with the Okta FIDO2 factor.
4. User completes phishing-resistance training module in the LMS, logged under
   the tag `mfa-training-2026`.
5. Help Desk closes ServiceNow ticket `TKT-ONB-*` associated with the hire.

## Revocation

Terminated users have tokens revoked from Okta and the hardware YubiKey is
collected at exit interview. Revocation event is logged under Splunk source
`okta_factor_lifecycle`.
