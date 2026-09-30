"""
Unit and Integration Tests for Cloud Compliance Auditor.
Tests rule evaluation logic, parsing accuracy, and compliance scoring.
"""

import unittest
import os
from engine.parser import TerraformParser
from engine.scanner import ComplianceScanner
from engine.rules import S3ServerSideEncryptionRule, SecurityGroupSSHExposureRule


class TestCloudComplianceAuditor(unittest.TestCase):

    def setUp(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.non_compliant_dir = os.path.join(self.base_dir, "terraform_samples", "non_compliant")
        self.compliant_dir = os.path.join(self.base_dir, "terraform_samples", "compliant")
        self.scanner = ComplianceScanner()

    def test_parser_extracts_resources(self):
        resources = TerraformParser.parse_directory(self.non_compliant_dir)
        self.assertGreater(len(resources), 0)
        types = [r.resource_type for r in resources]
        self.assertIn("aws_s3_bucket", types)
        self.assertIn("aws_security_group", types)
        self.assertIn("aws_db_instance", types)

    def test_non_compliant_scan_detects_violations(self):
        result = self.scanner.scan_directory(self.non_compliant_dir)
        self.assertLess(result.compliance_score, 100.0)
        self.assertGreater(result.severity_counts["CRITICAL"], 0)
        self.assertGreater(result.severity_counts["HIGH"], 0)
        
        # Verify specific critical rule triggered
        rule_ids = [f.rule_id for f in result.findings]
        self.assertIn("GRC-NET-001", rule_ids)  # SSH open to 0.0.0.0/0
        self.assertIn("GRC-S3-002", rule_ids)   # Missing Public Access Block
        self.assertIn("GRC-RDS-002", rule_ids)  # Public RDS instance

    def test_compliant_scan_passes_all_checks(self):
        result = self.scanner.scan_directory(self.compliant_dir)
        self.assertEqual(result.compliance_score, 100.0)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.severity_counts["CRITICAL"], 0)
        self.assertEqual(result.severity_counts["HIGH"], 0)

    def test_framework_filter(self):
        cis_result = self.scanner.scan_directory(self.non_compliant_dir, framework_filter="cis")
        for f in cis_result.findings:
            self.assertIn("CIS_AWS_v3.0", f.framework_mappings)


if __name__ == "__main__":
    unittest.main()
