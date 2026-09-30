"""
Core Scanner and Evaluation Engine for GRC Cloud Auditor.
Evaluates Terraform resources against defined compliance policies and aggregates metrics.
"""

from typing import List, Dict, Any, Optional
from .parser import TerraformParser, TerraformResource
from .rules import ALL_RULES, ComplianceRule, ComplianceFinding


class AuditResult:
    """Aggregates all findings, framework metrics, and compliance score."""
    def __init__(self, target_path: str, resources: List[TerraformResource], findings: List[ComplianceFinding], total_checks: int):
        self.target_path = target_path
        self.resources = resources
        self.findings = findings
        self.total_checks = total_checks
        self.passed_checks = max(0, total_checks - len(findings))
        
        # Calculate Compliance Score (0.0 to 100.0%)
        if self.total_checks > 0:
            self.compliance_score = round((self.passed_checks / self.total_checks) * 100, 1)
        else:
            self.compliance_score = 100.0

        # Severity Counts
        self.severity_counts = {
            "CRITICAL": sum(1 for f in findings if f.severity == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f.severity == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
            "LOW": sum(1 for f in findings if f.severity == "LOW")
        }

        # Framework Breakdown
        self.framework_stats: Dict[str, Dict[str, int]] = {
            "CIS_AWS_v3.0": {"total": 0, "failed": 0},
            "NIST_CSF_2.0": {"total": 0, "failed": 0},
            "SOC_2_Type_II": {"total": 0, "failed": 0},
            "ISO_27001_2022": {"total": 0, "failed": 0}
        }
        self._calculate_framework_stats()

    def _calculate_framework_stats(self):
        for rule in ALL_RULES:
            # count total checks executed for this rule
            applicable_resources = [r for r in self.resources if r.resource_type == rule.target_resource]
            num_applicable = len(applicable_resources)

            for fw in self.framework_stats.keys():
                if fw in rule.framework_mappings:
                    self.framework_stats[fw]["total"] += num_applicable

        for finding in self.findings:
            for fw in finding.framework_mappings.keys():
                if fw in self.framework_stats:
                    self.framework_stats[fw]["failed"] += 1

    def get_framework_percentage(self, framework_key: str) -> float:
        stats = self.framework_stats.get(framework_key, {"total": 0, "failed": 0})
        total = stats["total"]
        if total == 0:
            return 100.0
        passed = max(0, total - stats["failed"])
        return round((passed / total) * 100, 1)


class ComplianceScanner:
    """Orchestrates parsing, rule matching, and report generation."""

    def __init__(self, rules: Optional[List[ComplianceRule]] = None):
        self.rules = rules if rules is not None else ALL_RULES

    def scan_directory(self, directory_path: str, framework_filter: Optional[str] = None) -> AuditResult:
        """Parses directory and executes compliance audit."""
        resources = TerraformParser.parse_directory(directory_path)
        return self._evaluate_resources(resources, directory_path, framework_filter)

    def _evaluate_resources(
        self,
        resources: List[TerraformResource],
        target_path: str,
        framework_filter: Optional[str] = None
    ) -> AuditResult:
        findings: List[ComplianceFinding] = []
        total_checks = 0

        # Filter active rules if requested
        active_rules = self.rules
        if framework_filter:
            fw_key_map = {
                "cis": "CIS_AWS_v3.0",
                "nist": "NIST_CSF_2.0",
                "soc2": "SOC_2_Type_II",
                "iso27001": "ISO_27001_2022"
            }
            target_key = fw_key_map.get(framework_filter.lower(), framework_filter)
            active_rules = [r for r in self.rules if target_key in r.framework_mappings]

        for rule in active_rules:
            # Find matching target resources
            matching_resources = [r for r in resources if r.resource_type == rule.target_resource]
            for res in matching_resources:
                total_checks += 1
                finding = rule.evaluate(res, resources)
                if finding:
                    findings.append(finding)

        return AuditResult(target_path, resources, findings, total_checks)
