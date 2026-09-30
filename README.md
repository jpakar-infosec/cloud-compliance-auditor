# CloudGuard-GRC: Automated Cloud Compliance & Policy-as-Code Engine

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![GRC Frameworks](https://img.shields.io/badge/frameworks-CIS%20|%20NIST%20CSF%20|%20SOC%202%20|%20ISO%2027001-success.svg)](#framework-alignment)
[![Security Gate](https://img.shields.io/badge/shift--left-CI%2FCD%20Gate-orange.svg)](#cicd-compliance-gate)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20(pure%20python)-brightgreen.svg)](#architecture)

> **A portfolio project demonstrating modern Technical GRC (Governance, Risk, and Compliance) and Shift-Left Security Automation.**  
> Automatically audits Infrastructure-as-Code (Terraform) against **CIS AWS Foundations v3.0**, **NIST CSF 2.0**, **SOC 2 Type II**, and **ISO/IEC 27001:2022** baselines, generating auditor-ready evidence records and executive dashboards.

---

## 📌 Executive Problem Statement

In modern cloud environments, **over 80% of security breaches stem from preventable cloud misconfigurations** (e.g., exposed storage buckets, unrestricted administrative ports, and unencrypted databases). 

Traditional GRC approaches rely on periodic, manual audits (spreadsheets, retrospective questionnaires) that take weeks and are outdated the moment they are completed. **CloudGuard-GRC** implements **Continuous Compliance and Policy-as-Code (PaC)**:
1. **Shifts Compliance Left:** Evaluates Terraform infrastructure code *before* deployment.
2. **Automates Audit Evidence:** Produces timestamped, machine-readable JSON records satisfying external auditors.
3. **Enforces Governance:** Blocks non-compliant pull requests in CI/CD pipelines while providing engineers with exact remediation code.

---

## 🏗️ Architecture & Pipeline Flow

```
   ┌───────────────────────────────────────────────┐
   │             Developer / Engineer              │
   │      Submits Terraform Infrastructure PR      │
   └──────────────────────┬────────────────────────┘
                          │
                          ▼
   ┌───────────────────────────────────────────────┐
   │          GitHub Actions CI/CD Gate            │
   │         (.github/workflows/compliance.yml)    │
   └──────────────────────┬────────────────────────┘
                          │
                          ▼
   ┌───────────────────────────────────────────────┐
   │         Cloud Compliance Auditor Engine       │
   │   - Lightweight HCL Parser                    │
   │   - Rule Evaluation Engine (CIS / NIST / SOC2)│
   │   - Severity & Risk Scoring Matrix            │
   └───────┬───────────────────────────────┬───────┘
           │                               │
           ▼                               ▼
┌──────────────────────┐       ┌───────────────────────┐
│  Executive Reporting │       │ Auditor Evidence Pack │
│  - Terminal (ANSI)   │       │ - JSON Evidence       │
│  - Markdown Summary  │       │ - Framework Crosswalk │
│  - HTML Dashboard    │       │ - Policy Standards    │
└──────────────────────┘       └───────────────────────┘
```

---

## 🎯 Framework Alignment & Crosswalk

A single automated rule evaluation simultaneously validates controls across multiple industry standards:

| Rule ID | Finding Description | Severity | CIS AWS v3.0 | NIST CSF 2.0 | SOC 2 Type II | ISO 27001:2022 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GRC-S3-001` | S3 Server-Side Encryption (SSE) | **HIGH** | `2.1.1` | `PR.DS-01` | `CC6.6`, `CC6.7` | `A.8.24` |
| `GRC-S3-002` | S3 Public Access Block Enforced | **CRITICAL** | `2.1.5` | `PR.AC-05` | `CC6.1`, `CC6.6` | `A.5.15` |
| `GRC-S3-003` | S3 Object Versioning Enabled | **MEDIUM** | `2.1.3` | `PR.DS-02`, `PR.IR-01` | `A1.2` | `A.8.13` |
| `GRC-NET-001`| Inbound SSH (22) from `0.0.0.0/0` | **CRITICAL** | `5.2` | `PR.AC-05` | `CC6.6` | `A.8.20` |
| `GRC-NET-002`| Inbound RDP (3389) from `0.0.0.0/0` | **CRITICAL** | `5.3` | `PR.AC-05` | `CC6.6` | `A.8.20` |
| `GRC-NET-003`| Inbound Database from `0.0.0.0/0` | **CRITICAL** | `5.1` | `PR.AC-05` | `CC6.6`, `CC6.7` | `A.8.20` |
| `GRC-IAM-001`| Wildcard Admin IAM (`*`/`*`) | **HIGH** | `1.16` | `PR.AC-04` | `CC6.1`, `CC6.2` | `A.8.2` |
| `GRC-IAM-002`| Static User Access Keys | **MEDIUM** | `1.14` | `PR.AC-01` | `CC6.1` | `A.8.5` |
| `GRC-RDS-001`| RDS Storage Encryption at Rest | **HIGH** | `2.3.1` | `PR.DS-01` | `CC6.6`, `CC6.7` | `A.8.24` |
| `GRC-RDS-002`| Publicly Accessible Database | **CRITICAL** | `2.3.3` | `PR.AC-05` | `CC6.6` | `A.8.20` |
| `GRC-RDS-003`| Backup Retention < 7 Days | **MEDIUM** | `2.3.2` | `PR.IR-01` | `A1.2` | `A.8.13` |

*See [FRAMEWORK_MAPPING.md](FRAMEWORK_MAPPING.md) for full control narratives and [POLICY_STANDARDS.md](POLICY_STANDARDS.md) for the enterprise policy baseline.*

---

## 🚀 Quickstart & Usage

The auditor is built in pure Python 3 using the standard library. **No pip installs or external cloud accounts are required to run the audit locally.**

### 1. Scan Vulnerable Infrastructure (Demonstrating Detections)
```bash
python3 auditor.py terraform_samples/non_compliant --format all --fail-on NONE
```
*Outputs colorized ANSI terminal findings, and exports reports into `./reports/`:*
- `reports/compliance_report.md` (Executive Markdown report)
- `reports/compliance_evidence.json` (Auditor JSON evidence record)
- `reports/compliance_dashboard.html` (Interactive HTML dashboard)

### 2. Scan Hardened Infrastructure (Post-Remediation)
```bash
python3 auditor.py terraform_samples/compliant --format all
```
*Outputs:*
```text
OVERALL COMPLIANCE SCORE: 100.0% [COMPLIANT]
✔ ZERO COMPLIANCE VIOLATIONS DETECTED. Infrastructure meets all benchmark baselines.
```

### 3. Filter Audit by Specific Framework
Focus exclusively on SOC 2 or CIS controls:
```bash
python3 auditor.py terraform_samples/non_compliant --framework soc2
python3 auditor.py terraform_samples/non_compliant --framework cis
```

### 4. CI/CD Gatekeeper Enforcement
Configure the threshold at which the pipeline terminates (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`):
```bash
python3 auditor.py terraform_samples/non_compliant --fail-on HIGH
# Exits with exit code 1 if CRITICAL or HIGH findings exist (blocking the build)
```

### 5. Run Automated Test Suite
```bash
python3 -m unittest discover tests
```

---

## 📂 Repository Structure

```text
├── auditor.py                     # CLI entrypoint and orchestrator
├── engine/
│   ├── parser.py                  # Lightweight Terraform HCL parser
│   ├── rules.py                   # Compliance rules library with framework metadata
│   ├── scanner.py                 # Core evaluation and scoring engine
│   └── reporter.py                # Multi-format report and evidence generator
├── terraform_samples/
│   ├── non_compliant/             # Intentional misconfigurations (S3, SG, IAM, RDS)
│   └── compliant/                 # Hardened, auditor-approved infrastructure templates
├── .github/workflows/
│   └── compliance-gate.yml        # CI/CD pull request gatekeeper workflow
├── tests/
│   └── test_auditor.py            # Unit test suite verifying rule logic and scoring
├── POLICY_STANDARDS.md            # Enterprise Cloud Security Standard (Governance document)
├── FRAMEWORK_MAPPING.md           # Multi-framework crosswalk matrix
└── README.md                      # Project documentation and portfolio presentation
```

---

---

## 📜 License

MIT License. Feel free to adapt and expand this project for your own portfolio.
