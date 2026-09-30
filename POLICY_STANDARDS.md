# Enterprise Cloud Infrastructure Security Baseline Standard

**Document ID:** SEC-STD-CLOUD-004  
**Classification:** Internal Security Policy  
**Effective Date:** 2026-10-01  
**Owner:** Information Security & Governance (GRC Team)  
**Applies To:** All Engineering, DevOps, and Cloud Infrastructure Teams  

---

## 1. Purpose & Scope

The purpose of this standard is to establish mandatory technical baseline controls for all Infrastructure-as-Code (IaC) and cloud-hosted environments across the organization. This standard ensures adherence to **CIS AWS Foundations Benchmark v3.0**, **NIST CSF 2.0**, **SOC 2 Type II**, and **ISO/IEC 27001:2022**.

This policy applies to all Terraform modules, cloud accounts, environments (Production, Staging, Development), and workloads storing or processing organizational or customer data.

---

## 2. Policy Statements & Controls

### 2.1 Storage & Data Protection (S3)
* **SEC-S3-01 (Encryption at Rest):** All Amazon S3 buckets MUST enforce default Server-Side Encryption (SSE) utilizing either AWS Key Management Service (AWS KMS) customer-managed keys or AWS-managed keys (`aws:kms` or `AES256`).
* **SEC-S3-02 (Public Access Prevention):** All S3 buckets MUST enable Amazon S3 Block Public Access at the bucket or account level. Public read or write access control lists (ACLs) are strictly prohibited unless granted an approved business exception.
* **SEC-S3-03 (Data Integrity & Versioning):** All buckets designated as production or containing sensitive customer/audit data MUST enable S3 Object Versioning to protect against accidental deletion or ransomware modification.

### 2.2 Network Architecture & Perimeter Security (Security Groups)
* **SEC-NET-01 (Administrative Access Restriction):** Security group ingress rules MUST NEVER allow inbound traffic from `0.0.0.0/0` to administrative ports, including SSH (TCP port 22) and Windows RDP (TCP port 3389). Administrative access must be mediated via secure bastions or AWS Systems Manager (SSM) Session Manager.
* **SEC-NET-02 (Database Network Isolation):** Relational databases and datastores (e.g., PostgreSQL port 5432, MySQL port 3306) MUST NEVER have direct ingress from public CIDRs (`0.0.0.0/0`). Ingress must be restricted to private application subnet CIDRs or explicit application security groups.

### 2.3 Identity & Access Management (IAM)
* **SEC-IAM-01 (Least Privilege Enforcement):** IAM policies MUST adhere strictly to the Principle of Least Privilege (PoLP). Wildcard administrative policies (`Action: "*"` and `Resource: "*"`) are prohibited in production application roles.
* **SEC-IAM-02 (Ephemeral Credentials):** Automated deployment pipelines and services MUST utilize temporary IAM roles (e.g., GitHub Actions OpenID Connect / OIDC federated tokens or STS assume-role) rather than long-lived static IAM user access keys.

### 2.4 Database Security (Amazon RDS)
* **SEC-RDS-01 (Storage Encryption):** All RDS database instances MUST enable storage encryption at rest using AWS KMS.
* **SEC-RDS-02 (Public Accessibility):** RDS database instances MUST have `publicly_accessible` set to `false`. Database instances must reside in private isolated subnets without direct internet route tables.
* **SEC-RDS-03 (Backup Retention & Continuity):** Production database instances MUST maintain an automated backup retention period of at least 7 days (recommended 14–30 days) to satisfy Business Continuity and Disaster Recovery (BC/DR) SLAs.

---

## 3. Automated Enforcement & Shift-Left Compliance

To eliminate configuration drift and avoid retroactive remediation:
1. **CI/CD Quality Gate:** Every pull request containing Terraform files is automatically evaluated by the `cloud-compliance-auditor` engine.
2. **Build Termination:** Pull requests that introduce `CRITICAL` or `HIGH` severity infractions are automatically blocked from merging until resolved or an approved policy exception is recorded.
3. **Continuous Audit Evidence:** Every pipeline run generates a timestamped `compliance_evidence.json` artifact retained for annual SOC 2 and ISO 27001 auditor examination.

---

## 4. Policy Exceptions & Non-Conformity Process

If business requirements necessitate a deviation from this standard:
1. An official **Security Exception Request** must be filed with the GRC team via the Risk Register.
2. The request must include:
   - Specific control ID and affected resource ARN.
   - Justification and compensating controls (e.g., IP allowlisting, WAF inspection, enhanced audit logging).
   - Expiration date (exceptions are granted for a maximum of 90 days).
3. The exception requires documented sign-off from the Chief Information Security Officer (CISO).
