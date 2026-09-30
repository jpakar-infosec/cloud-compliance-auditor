# Governance Framework Crosswalk & Control Mapping Matrix

This document defines the multi-framework crosswalk mapping implemented by the `cloud-compliance-auditor` engine. A single automated technical check simultaneously satisfies control requirements across four primary compliance frameworks.

---

## 1. Multi-Framework Crosswalk Matrix

| Rule ID | Control Title | Severity | CIS AWS v3.0 | NIST CSF 2.0 | SOC 2 Type II | ISO/IEC 27001:2022 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **GRC-S3-001** | S3 Server-Side Encryption (SSE) | **HIGH** | `2.1.1` Default S3 Encryption | `PR.DS-01` Data-at-rest protection | `CC6.6`, `CC6.7` Encryption of customer data | `A.8.24` Use of cryptography |
| **GRC-S3-002** | S3 Public Access Block Enforced | **CRITICAL** | `2.1.5` S3 Public Access Block | `PR.AC-05` Network perimeter integrity | `CC6.1`, `CC6.6` Perimeter defense | `A.5.15` Access control |
| **GRC-S3-003** | S3 Object Versioning Enabled | **MEDIUM** | `2.1.3` S3 Bucket Versioning | `PR.DS-02`, `PR.IR-01` Integrity & recovery | `A1.2` Disaster recovery & environmental | `A.8.13` Information backup |
| **GRC-NET-001** | Block SSH (Port 22) from `0.0.0.0/0` | **CRITICAL** | `5.2` Security group ingress for SSH | `PR.AC-05` Network access restriction | `CC6.6` Logical boundary protection | `A.8.20` Network security |
| **GRC-NET-002** | Block RDP (Port 3389) from `0.0.0.0/0` | **CRITICAL** | `5.3` Security group ingress for RDP | `PR.AC-05` Network access restriction | `CC6.6` Logical boundary protection | `A.8.20` Network security |
| **GRC-NET-003** | Block Database Ports from `0.0.0.0/0` | **CRITICAL** | `5.1` Restrict VPC ingress | `PR.AC-05` Least privilege connectivity | `CC6.6`, `CC6.7` Data store isolation | `A.8.20` Network segmentation |
| **GRC-IAM-001** | Prevent Wildcard Admin IAM Policies | **HIGH** | `1.16` Least privilege IAM policies | `PR.AC-04` Principle of Least Privilege | `CC6.1`, `CC6.2` Authorization boundaries | `A.8.2` Privileged access rights |
| **GRC-IAM-002** | Restrict Static IAM User Keys | **MEDIUM** | `1.14` Credential rotation / minimization | `PR.AC-01` Credential lifecycle | `CC6.1` Credential issuance & security | `A.8.5` Secure authentication |
| **GRC-RDS-001** | RDS Storage Encryption at Rest | **HIGH** | `2.3.1` RDS Storage Encryption | `PR.DS-01` Data-at-rest protection | `CC6.6`, `CC6.7` Stored data protection | `A.8.24` Use of cryptography |
| **GRC-RDS-002** | RDS Public Endpoint Disabled | **CRITICAL** | `2.3.3` RDS Public Accessibility | `PR.AC-05` Network boundary isolation | `CC6.6` Boundary protection | `A.8.20` Network security |
| **GRC-RDS-003** | RDS Automated Backup Retention | **MEDIUM** | `2.3.2` RDS Automated Backups | `PR.IR-01` Disaster recovery resilience | `A1.2` Availability & business continuity | `A.8.13` Information backup |

---

## 2. Framework Narratives & Auditor Alignment

### NIST Cybersecurity Framework (CSF) 2.0
* **PR.AC (Protect: Access Control):** Enforces network boundary segmentation, blocks public administrative ingress, and ensures least-privilege IAM policies.
* **PR.DS (Protect: Data Security):** Validates default server-side encryption across object storage (S3) and relational datastores (RDS).
* **PR.IR (Protect: Incident Resilience) & DE.CM (Detect):** Enforces object versioning and multi-day database backups to guarantee rapid recovery in the event of ransomware or accidental loss.

### SOC 2 Type II (Trust Services Criteria)
* **Common Criteria CC6.1 - CC6.3 (Logical and Physical Access Controls):** Verified through IAM policy scoping, avoiding static access keys, and role-based permissions.
* **Common Criteria CC6.6 - CC6.7 (Boundary Protection & Data Transmission):** Verified by barring public ingress to ports 22, 3389, and database endpoints, as well as enforcing at-rest KMS encryption.
* **Availability A1.2 (Environmental and Operational Resilience):** Verified through mandatory snapshot retention and S3 object versioning.

### ISO/IEC 27001:2022 (Annex A)
* **A.5.15 (Access Control) & A.8.2 (Privileged Access Rights):** Prevention of wildcard IAM policies and public bucket access.
* **A.8.20 (Network Security):** Strict segmentation of database and management tiers via security group inspection.
* **A.8.24 (Use of Cryptography):** Validation of KMS key usage and cryptographic protection for data at rest.
