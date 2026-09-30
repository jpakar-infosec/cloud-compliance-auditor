#!/usr/bin/env python3
"""
Cloud Compliance Auditor (Policy-as-Code GRC Engine)
Audits Infrastructure-as-Code against CIS, NIST CSF 2.0, SOC 2, and ISO 27001 baselines.
"""

import sys
import os
import argparse
from engine.scanner import ComplianceScanner
from engine.reporter import AuditReporter


def main():
    parser = argparse.ArgumentParser(
        description="Audit Terraform Infrastructure against GRC Standards (CIS, NIST CSF 2.0, SOC 2, ISO 27001)"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default="terraform_samples/non_compliant",
        help="Path to directory containing Terraform (.tf) files (default: terraform_samples/non_compliant)"
    )
    parser.add_argument(
        "--format",
        choices=["console", "md", "json", "html", "all"],
        default="console",
        help="Output report format (default: console)"
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory to save generated reports (default: ./reports)"
    )
    parser.add_argument(
        "--framework",
        choices=["all", "cis", "nist", "soc2", "iso27001"],
        default="all",
        help="Filter audit checks by specific governance framework (default: all)"
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        default="HIGH",
        help="Exit with error code 1 if findings meet or exceed this severity threshold (default: HIGH)"
    )

    args = parser.parse_args()

    target_path = os.path.abspath(args.path)
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(2)

    scanner = ComplianceScanner()
    fw_filter = None if args.framework == "all" else args.framework
    result = scanner.scan_directory(target_path, framework_filter=fw_filter)

    # 1. Always show console summary unless strictly running in pipeline where only files are wanted
    AuditReporter.print_console(result)

    # 2. Export requested formats
    os.makedirs(args.output_dir, exist_ok=True)
    if args.format in ["md", "all"]:
        md_file = os.path.join(args.output_dir, "compliance_report.md")
        AuditReporter.generate_markdown(result, md_file)
        print(f"📄 Markdown Report generated: {md_file}")

    if args.format in ["json", "all"]:
        json_file = os.path.join(args.output_dir, "compliance_evidence.json")
        AuditReporter.generate_json_evidence(result, json_file)
        print(f"📋 JSON Audit Evidence Record generated: {json_file}")

    if args.format in ["html", "all"]:
        html_file = os.path.join(args.output_dir, "compliance_dashboard.html")
        AuditReporter.generate_html_dashboard(result, html_file)
        print(f"🌐 HTML Dashboard generated: {html_file}")

    # 3. Evaluate CI/CD Exit Code threshold
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 99}
    fail_threshold = severity_order.get(args.fail_on, 99)

    max_detected_severity = 0
    for finding in result.findings:
        sev_val = severity_order.get(finding.severity, 0)
        if sev_val > max_detected_severity:
            max_detected_severity = sev_val

    if max_detected_severity >= fail_threshold and fail_threshold < 99:
        print(f"\n[CI/CD GATE FAILED] Found violations matching or exceeding threshold '{args.fail_on}'.", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
