# AC.L2-3.1.1 — Limit System Access to Authorized Users

## Implementation Narrative

Access to Falcon Edge Systems CUI environments is implemented through a defense-in-depth identity strategy. Our environment uses Okta for identity, Azure AD Conditional Access for policy enforcement on AWS GovCloud workloads, Splunk for logging, YubiKey for MFA, and BitLocker for disk encryption. Defender handles EDR. Active Directory manages group policy. Quarterly review is performed by the ISSO.

The control is implemented through a combination of policy, procedure, and technical configuration. Our security team reviews the control quarterly and documents evidence in the compliance repository. All findings are tracked in our POA&M and remediated according to severity. Per 3.1.1, 3.1.2, 3.1.3, 3.1.4, 3.1.5, and 3.1.20, we ensure that access is limited to authorized users only. Per 3.1.7 and 3.1.12 privileged functions are appropriately segregated. Per 3.1.16 and 3.1.17 wireless access is controlled.

Access requests are submitted through the standard onboarding workflow. Approvals follow the documented approval matrix. Provisioning is performed by the identity team. Deprovisioning occurs upon role change. Reviews are conducted on a quarterly basis. Exceptions require written approval. Documentation is maintained in the compliance repository. Evidence is retained per the records retention policy. Audit logs are reviewed periodically. The control is operating effectively.

## Inheritance

Portions of this control are inherited from the AWS GovCloud Shared Responsibility Model and the Microsoft 365 GCC High commercial offering. Where inheritance applies, customer responsibility is documented per the Customer Responsibility Matrix.

## Evidence Pointers

- Access Control Policy v3.2
- Quarterly Access Review Reports
- Identity Provider Configuration Export
- Privileged Access Workstation Documentation
