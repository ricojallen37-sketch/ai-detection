# Wild Sample B — Human-Authored SSP Excerpt (NIST-style)

**Source description:** Written in the style of NIST SP 800-171 reference implementation guidance and real defense-contractor SSPs (e.g., the publicly available examples cited in Paramify's compliance library and DoD CIO sample documents). Specific systems, named owners, concrete dates, gaps acknowledged. This is what an SSP looks like when it has been authored by a human implementer who actually ran the work.

**Control: 3.1.1 Limit System Access to Authorized Users**

System access for the in-scope CUI environment (Northbridge Sub-Network, VLAN 412, documented in Network Topology Diagram NTD-2026-03) is enforced through Microsoft Entra ID Government, which is the identity provider for our M365 GCC High tenant (tenant ID redacted, contract under DFARS 252.204-7012). User accounts are provisioned via the HR onboarding workflow owned by D. Pena (HRIS Lead) and J. Kowalski (IT Operations Lead). Account creation requires written manager approval logged in our ticketing system (FreshService instance, contract # FS-2024-1184).

Quarterly access reviews are conducted by the IT Operations Lead and the relevant business unit manager. The most recent review was completed on March 17, 2026, and identified two stale accounts (former contractors) which were disabled within 24 hours of the finding. Evidence: ticket FS-2026-04412 and Entra audit log export retained in our evidence vault.

Known gap: privileged role activation is currently manual approval rather than PIM-enforced just-in-time access. POA&M item POAM-2026-014 tracks this finding, target closure July 2026.

**Control: 3.1.2 Limit System Access to Authorized Transactions and Functions**

Role-based access control is enforced via Entra ID security groups, with role definitions maintained in our role catalog (RACI-2026-Q1, owner: D. Pena). Sixty-three roles are currently defined across the in-scope environment. The mapping from role to system permissions is reviewed annually and was last validated by the IT Operations Lead on January 8, 2026.

Application-layer authorization for our CUI-handling design tools (PTC Creo, Mentor Graphics) is enforced via local SAML group claims. We acknowledge a limitation: not all third-party CAD tools support claims-based authorization, so for two legacy systems (listed in Asset Inventory line items 47 and 51) we rely on local user accounts gated by network ACLs. POA&M item POAM-2026-008 tracks the migration of these systems to a SAML-capable replacement, target closure December 2026.

**Control: 3.1.3 Control the Flow of CUI**

CUI flow is constrained to the Northbridge Sub-Network. Egress from this network to general-purpose internet is blocked at the Palo Alto PA-3220 firewall (configuration baseline PAN-2026-Q1, last reviewed February 4, 2026). Approved egress is limited to: (a) M365 GCC High endpoints (Microsoft-published IP ranges, refreshed monthly via automation), (b) the Lockheed Martin program portal (FQDN approved by program office, listed in our External Connection Inventory line item 12), and (c) NIST CRL/OCSP endpoints for certificate revocation.

Data loss prevention is enforced at the M365 layer using DLP policies authored by our Security Officer. The DLP policy set (policy ID DLP-CUI-2026) flags egress of files containing CUI marking strings or matching CUI document classifiers. Policy hits are reviewed weekly by the Security Officer; the most recent review (April 14, 2026) identified zero violations.

Known gap: USB removable media is currently controlled by Group Policy but not by a hardware DLP appliance. POA&M item POAM-2026-021 tracks the procurement and deployment of an endpoint DLP agent for USB control, target closure November 2026 to align with CMMC Phase 2 enforcement.
