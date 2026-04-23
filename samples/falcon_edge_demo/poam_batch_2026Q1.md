# POA&M Batch — Falcon Edge Systems Q1 2026

## Finding POAM-2026-001 — IA.L2-3.5.3 (Multi-Factor Authentication)

The control is implemented through a combination of policy, procedure, and technical configuration. Our security team reviews the control quarterly and documents evidence in the compliance repository. All findings are tracked in our POA&M and remediated according to severity. Per 3.5.3, 3.5.1, 3.5.2 the gap relates to MFA coverage on local privileged accounts on the legacy domain controller. The remediation plan is to implement YubiKey FIDO2 hardware tokens across all CUI access pathways including the legacy AD environment, integrated through Azure AD Conditional Access policy on the AWS GovCloud workloads. Closeout target is end of Q2.

## Finding POAM-2026-002 — SC.L2-3.13.1 (Boundary Protection)

The control is implemented through a combination of policy, procedure, and technical configuration. Our security team reviews the control quarterly and documents evidence in the compliance repository. All findings are tracked in our POA&M and remediated according to severity. Per 3.13.1, 3.13.2, 3.13.5, 3.13.6 the gap relates to inspection coverage on east-west traffic between the engineering subnet and the file storage tier. The remediation plan is to deploy additional inspection capacity and update the documented architecture diagrams. Closeout target is end of Q2.

## Finding POAM-2026-003 — SI.L2-3.14.1 (Flaw Remediation)

The control is implemented through a combination of policy, procedure, and technical configuration. Our security team reviews the control quarterly and documents evidence in the compliance repository. All findings are tracked in our POA&M and remediated according to severity. Per 3.14.1, 3.14.2, 3.14.3, 3.14.4 the gap relates to patch latency on the SolidWorks engineering workstations. The remediation plan is to implement automated patching cadence aligned with vendor advisories and document compensating controls during the patch window. Closeout target is end of Q2.

## Finding POAM-2026-004 — AT.L2-3.2.1 (Security Awareness Training)

The control is implemented through a combination of policy, procedure, and technical configuration. Our security team reviews the control quarterly and documents evidence in the compliance repository. All findings are tracked in our POA&M and remediated according to severity. Per 3.2.1, 3.2.2, 3.2.3 the gap relates to role-based training completion rates for engineering staff with privileged access. The remediation plan is to implement automated reminder workflows and quarterly training reporting cadence. Closeout target is end of Q2.
