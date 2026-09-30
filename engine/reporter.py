"""
GRC Audit Reporter.
Generates Console (ANSI), Markdown Executive Report, JSON Evidence Record, and HTML Dashboard.
"""

import os
import json
import datetime
from typing import Dict, Any
from .scanner import AuditResult


class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


class AuditReporter:
    """Formats and exports audit findings into various auditor and executive formats."""

    @staticmethod
    def print_console(result: AuditResult):
        """Renders rich ANSI terminal output."""
        print("\n" + "=" * 80)
        print(f"{Colors.BOLD}{Colors.CYAN} CLOUD COMPLIANCE & POLICY-AS-CODE AUDITOR (GRC ENGINE) {Colors.RESET}")
        print("=" * 80)
        print(f"Target Path: {Colors.BOLD}{result.target_path}{Colors.RESET}")
        print(f"Audit Timestamp: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}")
        print(f"Resources Scanned: {len(result.resources)} | Total Evaluated Checks: {result.total_checks}")

        # Score Banner
        score_color = Colors.GREEN if result.compliance_score >= 85 else (Colors.YELLOW if result.compliance_score >= 60 else Colors.RED)
        status_label = "COMPLIANT" if result.compliance_score == 100 else ("NEEDS REMEDIATION" if result.compliance_score >= 70 else "CRITICAL NON-COMPLIANCE")
        print("\n" + "-" * 80)
        print(f" {Colors.BOLD}OVERALL COMPLIANCE SCORE:{Colors.RESET} {score_color}{Colors.BOLD}{result.compliance_score}%{Colors.RESET} [{score_color}{status_label}{Colors.RESET}]")
        print("-" * 80)

        # Severity Summary
        print(f"\n{Colors.BOLD}FINDINGS SEVERITY BREAKDOWN:{Colors.RESET}")
        print(f"  {Colors.RED}● CRITICAL:{Colors.RESET} {result.severity_counts['CRITICAL']}")
        print(f"  {Colors.YELLOW}● HIGH:{Colors.RESET}     {result.severity_counts['HIGH']}")
        print(f"  {Colors.BLUE}● MEDIUM:{Colors.RESET}   {result.severity_counts['MEDIUM']}")
        print(f"  ● LOW:      {result.severity_counts['LOW']}")

        # Framework Breakdown
        print(f"\n{Colors.BOLD}FRAMEWORK ALIGNMENT BREAKDOWN:{Colors.RESET}")
        for fw_key, label in [
            ("CIS_AWS_v3.0", "CIS AWS Foundations v3.0"),
            ("NIST_CSF_2.0", "NIST Cybersecurity Framework 2.0"),
            ("SOC_2_Type_II", "SOC 2 Type II (Trust Services)"),
            ("ISO_27001_2022", "ISO/IEC 27001:2022")
        ]:
            fw_score = result.get_framework_percentage(fw_key)
            fw_color = Colors.GREEN if fw_score >= 85 else (Colors.YELLOW if fw_score >= 60 else Colors.RED)
            failed_count = result.framework_stats[fw_key]["failed"]
            total_count = result.framework_stats[fw_key]["total"]
            print(f"  • {label:<35} {fw_color}{fw_score:>5.1f}%{Colors.RESET} ({total_count - failed_count}/{total_count} controls met)")

        # Detailed Findings
        if not result.findings:
            print(f"\n{Colors.GREEN}{Colors.BOLD}✔ ZERO COMPLIANCE VIOLATIONS DETECTED. Infrastructure meets all benchmark baselines.{Colors.RESET}\n")
            return

        print(f"\n{Colors.BOLD}{'=' * 30} DETAILED FINDINGS ({len(result.findings)}) {'=' * 30}{Colors.RESET}\n")
        for idx, finding in enumerate(result.findings, 1):
            sev_color = Colors.RED if finding.severity in ["CRITICAL", "HIGH"] else Colors.YELLOW
            print(f"[{idx}] {sev_color}{Colors.BOLD}[{finding.severity}] {finding.rule_id}: {finding.title}{Colors.RESET}")
            print(f"    Resource:   {Colors.CYAN}{finding.resource_type}.{finding.resource_name}{Colors.RESET}")
            print(f"    Location:   {finding.file_path}:{finding.line_number}")
            print(f"    Issue:      {finding.description}")
            print(f"    Frameworks: {', '.join(f'{k} ({v})' for k, v in finding.framework_mappings.items())}")
            print(f"    {Colors.GREEN}Remediation:{Colors.RESET} {finding.remediation}")
            print("    " + "-" * 74)

        print("\n" + "=" * 80 + "\n")

    @staticmethod
    def generate_markdown(result: AuditResult, output_file: str):
        """Generates an Executive GRC Markdown Report."""
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        status = "COMPLIANT" if result.compliance_score == 100 else ("NEEDS ATTENTION" if result.compliance_score >= 70 else "NON-COMPLIANT")

        lines = [
            "# Executive Cloud Compliance & Security Audit Report",
            "",
            f"**Audit Date:** `{now_str}`  ",
            f"**Target Scope:** `{result.target_path}`  ",
            f"**Assessor:** Automated Policy-as-Code Engine (`cloud-compliance-auditor`)  ",
            f"**Overall Compliance Posture:** `{status}` ({result.compliance_score}%)  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            "This report summarizes the compliance posture and baseline security control evaluation of the Infrastructure-as-Code (Terraform) templates. "
            "Automated shift-left security analysis was performed across four industry-standard governance frameworks: **CIS AWS Foundations Benchmark v3.0**, **NIST CSF 2.0**, **SOC 2 Type II**, and **ISO/IEC 27001:2022**.",
            "",
            "### Key Posture Metrics",
            f"- **Overall Compliance Score:** `{result.compliance_score}%`",
            f"- **Resources Assessed:** `{len(result.resources)}`",
            f"- **Total Control Checks:** `{result.total_checks}`",
            f"- **Controls Passed:** `{result.passed_checks}`",
            f"- **Controls Failed:** `{len(result.findings)}`",
            "",
            "### Risk Severity Distribution",
            "| Severity | Total Findings | Status / Action Required |",
            "| :--- | :--- | :--- |",
            f"| 🔴 **CRITICAL** | `{result.severity_counts['CRITICAL']}` | Immediate remediation required before production deployment. |",
            f"| 🟠 **HIGH** | `{result.severity_counts['HIGH']}` | Remediation required within 7 days. |",
            f"| 🟡 **MEDIUM** | `{result.severity_counts['MEDIUM']}` | Plan remediation in upcoming sprint. |",
            f"| 🔵 **LOW** | `{result.severity_counts['LOW']}` | Best practice enhancement. |",
            "",
            "---",
            "",
            "## 2. Framework Alignment & Gap Analysis",
            "",
            "| Governance Framework | Compliance Score | Met / Total Controls | Assessment Status |",
            "| :--- | :--- | :--- | :--- |",
        ]

        for fw_key, label in [
            ("CIS_AWS_v3.0", "CIS AWS Foundations v3.0"),
            ("NIST_CSF_2.0", "NIST Cybersecurity Framework 2.0"),
            ("SOC_2_Type_II", "SOC 2 Type II (Trust Services Criteria)"),
            ("ISO_27001_2022", "ISO/IEC 27001:2022")
        ]:
            fw_score = result.get_framework_percentage(fw_key)
            passed = result.framework_stats[fw_key]["total"] - result.framework_stats[fw_key]["failed"]
            total = result.framework_stats[fw_key]["total"]
            fw_status = "✅ Satisfied" if fw_score == 100 else ("⚠️ Deficiencies Noted" if fw_score >= 70 else "❌ High Risk Gaps")
            lines.append(f"| **{label}** | `{fw_score}%` | `{passed} / {total}` | {fw_status} |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Detailed Audit Findings & Remediation Roadmap",
            ""
        ])

        if not result.findings:
            lines.append("✅ **No non-compliant configurations detected.** All resources adhere to baseline policies.")
        else:
            for idx, finding in enumerate(result.findings, 1):
                lines.extend([
                    f"### Finding {idx}: [{finding.severity}] {finding.title}",
                    f"- **Rule ID:** `{finding.rule_id}`",
                    f"- **Resource:** `{finding.resource_type}.{finding.resource_name}`",
                    f"- **Location:** `{os.path.basename(finding.file_path)}:{finding.line_number}`",
                    f"- **Description:** {finding.description}",
                    "- **Framework Mappings:**",
                ])
                for fw, ctrl in finding.framework_mappings.items():
                    lines.append(f"  - **{fw}:** `{ctrl}`")
                lines.extend([
                    f"- **Remediation Action:** {finding.remediation}",
                    ""
                ])

        lines.extend([
            "---",
            "",
            "## 4. Auditor Sign-Off & Verification",
            "",
            "This report constitutes automated documentary evidence for internal and external audit reviews.",
            "",
            "| Role | Name | Title | Date | Signature |",
            "| :--- | :--- | :--- | :--- | :--- |",
            "| Lead Security Assessor | GRC Automation Engine | Continuous Compliance Auditor | " + now_str[:10] + " | *[Verified]* |",
            "| Cloud Security Lead | Pending Review | Head of Information Security | | |",
            ""
        ])

        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    @staticmethod
    def generate_json_evidence(result: AuditResult, output_file: str):
        """Generates machine-readable JSON compliance evidence record."""
        evidence = {
            "metadata": {
                "tool": "cloud-compliance-auditor",
                "version": "1.0.0",
                "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "target_path": result.target_path,
                "overall_compliance_score": result.compliance_score,
                "total_resources": len(result.resources),
                "total_checks": result.total_checks,
                "passed_checks": result.passed_checks,
                "failed_checks": len(result.findings)
            },
            "severity_summary": result.severity_counts,
            "framework_scores": {
                fw: {
                    "compliance_percentage": result.get_framework_percentage(fw),
                    "controls_passed": result.framework_stats[fw]["total"] - result.framework_stats[fw]["failed"],
                    "controls_total": result.framework_stats[fw]["total"]
                }
                for fw in result.framework_stats.keys()
            },
            "findings": [f.to_dict() for f in result.findings]
        }

        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    @staticmethod
    def generate_html_dashboard(result: AuditResult, output_file: str):
        """Generates an executive-ready HTML compliance dashboard."""
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        score_color = "#10b981" if result.compliance_score >= 85 else ("#f59e0b" if result.compliance_score >= 60 else "#ef4444")

        findings_html = ""
        for idx, f in enumerate(result.findings, 1):
            badge_color = "#ef4444" if f.severity == "CRITICAL" else ("#f97316" if f.severity == "HIGH" else "#3b82f6")
            fw_list = "".join(f"<span class='fw-tag'><b>{k}:</b> {v}</span> " for k, v in f.framework_mappings.items())
            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge" style="background-color: {badge_color};">{f.severity}</span>
                    <span class="finding-title"><b>{f.rule_id}:</b> {f.title}</span>
                </div>
                <div class="finding-meta">
                    <b>Resource:</b> <code>{f.resource_type}.{f.resource_name}</code> &nbsp;|&nbsp;
                    <b>File:</b> <code>{os.path.basename(f.file_path)}:{f.line_number}</code>
                </div>
                <div class="finding-desc">{f.description}</div>
                <div class="finding-frameworks">{fw_list}</div>
                <div class="finding-remediation"><b>Remediation:</b> {f.remediation}</div>
            </div>
            """

        if not result.findings:
            findings_html = "<div class='no-findings'>✅ <b>Zero compliance violations detected!</b> All configurations satisfy baseline security benchmarks.</div>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cloud Compliance Audit Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 20px; margin-bottom: 24px; }}
        h1 {{ font-size: 24px; margin: 0; color: #38bdf8; }}
        .meta-text {{ font-size: 13px; color: #94a3b8; }}
        .score-cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 20px; border: 1px solid #334155; text-align: center; }}
        .card-num {{ font-size: 32px; font-weight: bold; margin-top: 8px; }}
        .score-card {{ border-color: {score_color}; }}
        .table-section {{ background: #1e293b; border-radius: 8px; padding: 20px; border: 1px solid #334155; margin-bottom: 24px; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th, td {{ padding: 12px; border-bottom: 1px solid #334155; }}
        th {{ color: #94a3b8; font-weight: 600; font-size: 13px; text-transform: uppercase; }}
        .finding-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
        .finding-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .finding-title {{ font-size: 16px; color: #f8fafc; }}
        .finding-meta {{ font-size: 13px; color: #94a3b8; margin-bottom: 8px; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 13px; color: #38bdf8; }}
        .finding-desc {{ font-size: 14px; margin-bottom: 10px; color: #cbd5e1; }}
        .finding-frameworks {{ margin-bottom: 10px; }}
        .fw-tag {{ display: inline-block; background: #334155; padding: 3px 8px; border-radius: 4px; font-size: 11px; margin-right: 6px; margin-bottom: 4px; }}
        .finding-remediation {{ background: #064e3b; border-left: 4px solid #10b981; padding: 8px 12px; border-radius: 4px; font-size: 13px; color: #a7f3d0; }}
        .no-findings {{ background: #064e3b; border: 1px solid #10b981; border-radius: 8px; padding: 20px; text-align: center; color: #a7f3d0; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Cloud Compliance Audit Dashboard</h1>
                <div class="meta-text">Target: {result.target_path} | Generated: {now_str} UTC</div>
            </div>
            <div class="meta-text">Engine: Policy-as-Code v1.0.0</div>
        </header>

        <div class="score-cards">
            <div class="card score-card">
                <div class="meta-text">COMPLIANCE SCORE</div>
                <div class="card-num" style="color: {score_color};">{result.compliance_score}%</div>
            </div>
            <div class="card">
                <div class="meta-text">CRITICAL RISKS</div>
                <div class="card-num" style="color: #ef4444;">{result.severity_counts['CRITICAL']}</div>
            </div>
            <div class="card">
                <div class="meta-text">HIGH RISKS</div>
                <div class="card-num" style="color: #f97316;">{result.severity_counts['HIGH']}</div>
            </div>
            <div class="card">
                <div class="meta-text">CHECKS PASSED</div>
                <div class="card-num" style="color: #10b981;">{result.passed_checks} / {result.total_checks}</div>
            </div>
        </div>

        <div class="table-section">
            <h2 style="font-size: 18px; margin-top: 0; color: #38bdf8;">Framework Alignment Breakdown</h2>
            <table>
                <thead>
                    <tr>
                        <th>Governance Framework</th>
                        <th>Compliance Rate</th>
                        <th>Controls Satisfied</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><b>CIS AWS Foundations Benchmark v3.0</b></td>
                        <td><b>{result.get_framework_percentage('CIS_AWS_v3.0')}%</b></td>
                        <td>{result.framework_stats['CIS_AWS_v3.0']['total'] - result.framework_stats['CIS_AWS_v3.0']['failed']} / {result.framework_stats['CIS_AWS_v3.0']['total']}</td>
                    </tr>
                    <tr>
                        <td><b>NIST Cybersecurity Framework 2.0</b></td>
                        <td><b>{result.get_framework_percentage('NIST_CSF_2.0')}%</b></td>
                        <td>{result.framework_stats['NIST_CSF_2.0']['total'] - result.framework_stats['NIST_CSF_2.0']['failed']} / {result.framework_stats['NIST_CSF_2.0']['total']}</td>
                    </tr>
                    <tr>
                        <td><b>SOC 2 Type II (Trust Services Criteria)</b></td>
                        <td><b>{result.get_framework_percentage('SOC_2_Type_II')}%</b></td>
                        <td>{result.framework_stats['SOC_2_Type_II']['total'] - result.framework_stats['SOC_2_Type_II']['failed']} / {result.framework_stats['SOC_2_Type_II']['total']}</td>
                    </tr>
                    <tr>
                        <td><b>ISO/IEC 27001:2022</b></td>
                        <td><b>{result.get_framework_percentage('ISO_27001_2022')}%</b></td>
                        <td>{result.framework_stats['ISO_27001_2022']['total'] - result.framework_stats['ISO_27001_2022']['failed']} / {result.framework_stats['ISO_27001_2022']['total']}</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <h2 style="font-size: 18px; margin-top: 32px; color: #38bdf8;">Audit Findings & Remediation Roadmap</h2>
        {findings_html}
    </div>
</body>
</html>
"""
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)
