"""
Compliance Rules Library for GRC Cloud Auditor.
Maps technical configurations to CIS, NIST CSF 2.0, SOC 2, and ISO 27001 controls.
"""

from typing import Dict, List, Optional, Any
from .parser import TerraformResource


class ComplianceFinding:
    """Represents an individual audit violation finding."""
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        resource: TerraformResource,
        description: str,
        framework_mappings: Dict[str, str],
        remediation: str,
        file_path: str,
        line_number: int
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW
        self.resource_type = resource.resource_type
        self.resource_name = resource.resource_name
        self.description = description
        self.framework_mappings = framework_mappings
        self.remediation = remediation
        self.file_path = file_path
        self.line_number = line_number

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "resource": f"{self.resource_type}.{self.resource_name}",
            "file": self.file_path,
            "line": self.line_number,
            "description": self.description,
            "frameworks": self.framework_mappings,
            "remediation": self.remediation
        }


class ComplianceRule:
    """Base class for defining an auditor rule."""
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        target_resource: str,
        framework_mappings: Dict[str, str],
        description: str,
        remediation: str
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.target_resource = target_resource
        self.framework_mappings = framework_mappings
        self.description = description
        self.remediation = remediation

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        """Returns a ComplianceFinding if non-compliant, else None."""
        raise NotImplementedError


# --- S3 RULES ---

class S3ServerSideEncryptionRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-S3-001",
            title="S3 Bucket Default Server-Side Encryption (SSE) Not Configured",
            severity="HIGH",
            target_resource="aws_s3_bucket",
            framework_mappings={
                "CIS_AWS_v3.0": "2.1.1 - S3 Bucket Default Encryption",
                "NIST_CSF_2.0": "PR.DS-01 - Data-at-rest protected",
                "SOC_2_Type_II": "CC6.6 / CC6.7 - Encryption of Data at Rest",
                "ISO_27001_2022": "A.8.24 - Use of Cryptography"
            },
            description="S3 bucket does not have customer or AWS-managed server-side encryption enabled at rest.",
            remediation="Attach an 'aws_s3_bucket_server_side_encryption_configuration' resource referencing this bucket."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        # Check if companion aws_s3_bucket_server_side_encryption_configuration exists
        has_encryption = False
        for r in all_resources:
            if r.resource_type == "aws_s3_bucket_server_side_encryption_configuration":
                bucket_ref = str(r.attributes.get("bucket", ""))
                if resource.resource_name in bucket_ref or resource.attributes.get("bucket", "") in bucket_ref:
                    has_encryption = True
                    break
            # Or legacy inline server_side_encryption_configuration block
            if r == resource and "server_side_encryption_configuration" in resource.blocks:
                has_encryption = True
                break

        if not has_encryption:
            return ComplianceFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource=resource,
                description=f"Bucket '{resource.resource_name}' does not enforce server-side encryption.",
                framework_mappings=self.framework_mappings,
                remediation=self.remediation,
                file_path=resource.file_path,
                line_number=resource.line_number
            )
        return None


class S3PublicAccessBlockRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-S3-002",
            title="S3 Bucket Public Access Block Not Enforced",
            severity="CRITICAL",
            target_resource="aws_s3_bucket",
            framework_mappings={
                "CIS_AWS_v3.0": "2.1.5 - S3 Public Access Block",
                "NIST_CSF_2.0": "PR.AC-05 - Network integrity & access enforcement",
                "SOC_2_Type_II": "CC6.1 / CC6.6 - Perimeter defense & unauthorized access",
                "ISO_27001_2022": "A.5.15 - Access Control"
            },
            description="S3 bucket is not protected by an aws_s3_bucket_public_access_block resource, risking public exposure.",
            remediation="Configure 'aws_s3_bucket_public_access_block' with all 4 block settings set to true."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        # Check for companion aws_s3_bucket_public_access_block
        has_block = False
        for r in all_resources:
            if r.resource_type == "aws_s3_bucket_public_access_block":
                bucket_ref = str(r.attributes.get("bucket", ""))
                if resource.resource_name in bucket_ref or resource.attributes.get("bucket", "") in bucket_ref:
                    # Verify block properties
                    if (r.attributes.get("block_public_acls") is True and
                        r.attributes.get("block_public_policy") is True and
                        r.attributes.get("restrict_public_buckets") is True):
                        has_block = True
                        break

        # Check for direct ACL violation
        for r in all_resources:
            if r.resource_type == "aws_s3_bucket_acl":
                bucket_ref = str(r.attributes.get("bucket", ""))
                if (resource.resource_name in bucket_ref or resource.attributes.get("bucket", "") in bucket_ref):
                    if r.attributes.get("acl") in ["public-read", "public-read-write", "website"]:
                        has_block = False
                        break

        if not has_block:
            return ComplianceFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource=resource,
                description=f"Bucket '{resource.resource_name}' lacks complete public access restrictions or allows public read.",
                framework_mappings=self.framework_mappings,
                remediation=self.remediation,
                file_path=resource.file_path,
                line_number=resource.line_number
            )
        return None


class S3VersioningRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-S3-003",
            title="S3 Bucket Object Versioning Disabled",
            severity="MEDIUM",
            target_resource="aws_s3_bucket",
            framework_mappings={
                "CIS_AWS_v3.0": "2.1.3 - S3 Object Versioning",
                "NIST_CSF_2.0": "PR.DS-02 / PR.IR-01 - Data integrity and recovery",
                "SOC_2_Type_II": "A1.2 - Backup and environmental controls",
                "ISO_27001_2022": "A.8.13 - Information Backup"
            },
            description="Versioning protects against accidental deletion, tampering, and ransomware encryption.",
            remediation="Add an 'aws_s3_bucket_versioning' resource with status = 'Enabled'."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        has_versioning = False
        for r in all_resources:
            if r.resource_type == "aws_s3_bucket_versioning":
                bucket_ref = str(r.attributes.get("bucket", ""))
                if resource.resource_name in bucket_ref or resource.attributes.get("bucket", "") in bucket_ref:
                    # check block
                    v_blocks = r.blocks.get("versioning_configuration", [])
                    for vb in v_blocks:
                        if vb.get("status") == "Enabled":
                            has_versioning = True
                            break
                    if r.attributes.get("status") == "Enabled":
                        has_versioning = True
                    break

        if not has_versioning:
            return ComplianceFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource=resource,
                description=f"Bucket '{resource.resource_name}' does not have object versioning enabled.",
                framework_mappings=self.framework_mappings,
                remediation=self.remediation,
                file_path=resource.file_path,
                line_number=resource.line_number
            )
        return None


# --- NETWORK & SECURITY GROUP RULES ---

class SecurityGroupSSHExposureRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-NET-001",
            title="Security Group Allows Inbound SSH (Port 22) from Internet (0.0.0.0/0)",
            severity="CRITICAL",
            target_resource="aws_security_group",
            framework_mappings={
                "CIS_AWS_v3.0": "5.2 - Ensure no security groups allow ingress to port 22 from 0.0.0.0/0",
                "NIST_CSF_2.0": "PR.AC-05 - Network perimeter enforcement",
                "SOC_2_Type_II": "CC6.6 - Perimeter defense & boundaries",
                "ISO_27001_2022": "A.8.20 - Network Security"
            },
            description="Exposing port 22 directly to the public internet enables brute force and remote exploitation attacks.",
            remediation="Restrict SSH ingress to specific trusted corporate IP/CIDR or use AWS Systems Manager (SSM) Session Manager."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        ingress_blocks = resource.blocks.get("ingress", [])
        for block in ingress_blocks:
            from_port = block.get("from_port")
            to_port = block.get("to_port")
            cidrs = block.get("cidr_blocks", [])

            if isinstance(cidrs, list) and ("0.0.0.0/0" in cidrs or '["0.0.0.0/0"]' in str(cidrs)):
                if (from_port is not None and to_port is not None):
                    try:
                        fp, tp = int(from_port), int(to_port)
                        if fp <= 22 <= tp:
                            return ComplianceFinding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                resource=resource,
                                description=f"Security group '{resource.resource_name}' exposes port 22 to 0.0.0.0/0.",
                                framework_mappings=self.framework_mappings,
                                remediation=self.remediation,
                                file_path=resource.file_path,
                                line_number=resource.line_number
                            )
                    except ValueError:
                        pass
        return None


class SecurityGroupRDPExposureRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-NET-002",
            title="Security Group Allows Inbound RDP (Port 3389) from Internet (0.0.0.0/0)",
            severity="CRITICAL",
            target_resource="aws_security_group",
            framework_mappings={
                "CIS_AWS_v3.0": "5.3 - Ensure no security groups allow ingress to port 3389 from 0.0.0.0/0",
                "NIST_CSF_2.0": "PR.AC-05 - Network perimeter enforcement",
                "SOC_2_Type_II": "CC6.6 - Perimeter defense & boundaries",
                "ISO_27001_2022": "A.8.20 - Network Security"
            },
            description="Exposing Windows Remote Desktop Protocol (RDP) to the internet invites automated credential stuffing and ransomware.",
            remediation="Remove 0.0.0.0/0 ingress on port 3389 and mandate VPN or Guacamole/Bastion architecture."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        ingress_blocks = resource.blocks.get("ingress", [])
        for block in ingress_blocks:
            from_port = block.get("from_port")
            to_port = block.get("to_port")
            cidrs = block.get("cidr_blocks", [])

            if isinstance(cidrs, list) and ("0.0.0.0/0" in cidrs or '["0.0.0.0/0"]' in str(cidrs)):
                if from_port is not None and to_port is not None:
                    try:
                        fp, tp = int(from_port), int(to_port)
                        if fp <= 3389 <= tp:
                            return ComplianceFinding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                resource=resource,
                                description=f"Security group '{resource.resource_name}' exposes RDP (3389) to 0.0.0.0/0.",
                                framework_mappings=self.framework_mappings,
                                remediation=self.remediation,
                                file_path=resource.file_path,
                                line_number=resource.line_number
                            )
                    except ValueError:
                        pass
        return None


class SecurityGroupDatabaseExposureRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-NET-003",
            title="Security Group Exposes Database Ports Directly to 0.0.0.0/0",
            severity="CRITICAL",
            target_resource="aws_security_group",
            framework_mappings={
                "CIS_AWS_v3.0": "5.1 - VPC Security Group Ingress Restrictions",
                "NIST_CSF_2.0": "PR.AC-05 - Least privilege network connectivity",
                "SOC_2_Type_II": "CC6.6 / CC6.7 - Network segmentation & data stores",
                "ISO_27001_2022": "A.8.20 - Network Segmentation"
            },
            description="Exposing database ports (e.g., PostgreSQL 5432, MySQL 3306, MongoDB 27017) invites direct unauthorized access.",
            remediation="Restrict database ingress to private application subnet CIDRs or application security group IDs."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        db_ports = {5432, 3306, 1433, 1521, 27017, 6379}
        ingress_blocks = resource.blocks.get("ingress", [])
        for block in ingress_blocks:
            from_port = block.get("from_port")
            to_port = block.get("to_port")
            cidrs = block.get("cidr_blocks", [])

            if isinstance(cidrs, list) and ("0.0.0.0/0" in cidrs or '["0.0.0.0/0"]' in str(cidrs)):
                if from_port is not None and to_port is not None:
                    try:
                        fp, tp = int(from_port), int(to_port)
                        for port in db_ports:
                            if fp <= port <= tp:
                                return ComplianceFinding(
                                    rule_id=self.rule_id,
                                    title=self.title,
                                    severity=self.severity,
                                    resource=resource,
                                    description=f"Security group '{resource.resource_name}' exposes database port {port} to 0.0.0.0/0.",
                                    framework_mappings=self.framework_mappings,
                                    remediation=self.remediation,
                                    file_path=resource.file_path,
                                    line_number=resource.line_number
                                )
                    except ValueError:
                        pass
        return None


# --- IAM RULES ---

class IAMAdminWildcardRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-IAM-001",
            title="IAM Policy Grants Wildcard Full Administrative Privileges",
            severity="HIGH",
            target_resource="aws_iam_policy",
            framework_mappings={
                "CIS_AWS_v3.0": "1.16 - Ensure IAM policies adhere to least privilege",
                "NIST_CSF_2.0": "PR.AC-04 - Principle of Least Privilege",
                "SOC_2_Type_II": "CC6.1 / CC6.2 - Logical access authorization",
                "ISO_27001_2022": "A.8.2 - Privileged access rights"
            },
            description="Policy specifies Action: '*' and Resource: '*', granting unrestricted administrative privileges.",
            remediation="Scope down policy statement to specific API actions and explicit resource ARNs."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        raw_text = resource.raw_text
        if '"Action": "*"' in raw_text or 'Action = "*"' in raw_text or '"Action": ["*"]' in raw_text:
            if '"Resource": "*"' in raw_text or 'Resource = "*"' in raw_text or '"Resource": ["*"]' in raw_text:
                return ComplianceFinding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    resource=resource,
                    description=f"IAM Policy '{resource.resource_name}' grants blanket Action='*' across Resource='*'.",
                    framework_mappings=self.framework_mappings,
                    remediation=self.remediation,
                    file_path=resource.file_path,
                    line_number=resource.line_number
                )
        return None


class IAMStaticAccessKeyRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-IAM-002",
            title="Static IAM User Access Key Provisioned",
            severity="MEDIUM",
            target_resource="aws_iam_access_key",
            framework_mappings={
                "CIS_AWS_v3.0": "1.14 - Minimize static credentials and rotate access keys",
                "NIST_CSF_2.0": "PR.AC-01 - Identity and credential management",
                "SOC_2_Type_II": "CC6.1 - Credential issuance & security",
                "ISO_27001_2022": "A.8.5 - Secure Authentication"
            },
            description="Static programmatic access keys represent high credential leakage risk.",
            remediation="Migrate workloads to IAM Roles (OIDC for CI/CD, Instance Profiles for compute, or STS temporary credentials)."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        return ComplianceFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            resource=resource,
            description=f"Static access key '{resource.resource_name}' generated for user. Prefer short-lived tokens.",
            framework_mappings=self.framework_mappings,
            remediation=self.remediation,
            file_path=resource.file_path,
            line_number=resource.line_number
        )


# --- DATABASE / RDS RULES ---

class RDSEncryptionAtRestRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-RDS-001",
            title="RDS Instance Storage Encryption Disabled",
            severity="HIGH",
            target_resource="aws_db_instance",
            framework_mappings={
                "CIS_AWS_v3.0": "2.3.1 - RDS Storage Encryption",
                "NIST_CSF_2.0": "PR.DS-01 - Protection of sensitive data at rest",
                "SOC_2_Type_II": "CC6.6 / CC6.7 - Encryption of stored customer data",
                "ISO_27001_2022": "A.8.24 - Use of Cryptography"
            },
            description="Database storage is not encrypted at rest using AWS KMS.",
            remediation="Set 'storage_encrypted = true' and specify a customer-managed KMS key ARN."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        storage_enc = resource.attributes.get("storage_encrypted")
        if storage_enc is False or storage_enc is None:
            return ComplianceFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource=resource,
                description=f"RDS instance '{resource.resource_name}' has storage encryption set to false or unconfigured.",
                framework_mappings=self.framework_mappings,
                remediation=self.remediation,
                file_path=resource.file_path,
                line_number=resource.line_number
            )
        return None


class RDSPublicAccessRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-RDS-002",
            title="RDS Instance Configured as Publicly Accessible",
            severity="CRITICAL",
            target_resource="aws_db_instance",
            framework_mappings={
                "CIS_AWS_v3.0": "2.3.3 - RDS Public Accessibility",
                "NIST_CSF_2.0": "PR.AC-05 - Network segmentation and isolation",
                "SOC_2_Type_II": "CC6.6 - Perimeter defense & boundaries",
                "ISO_27001_2022": "A.8.20 - Network Security"
            },
            description="Database endpoint is assigned a public IP and accessible over public routing tables.",
            remediation="Set 'publicly_accessible = false' and isolate within private DB subnets."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        publicly_acc = resource.attributes.get("publicly_accessible")
        if publicly_acc is True:
            return ComplianceFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource=resource,
                description=f"RDS instance '{resource.resource_name}' has 'publicly_accessible = true'.",
                framework_mappings=self.framework_mappings,
                remediation=self.remediation,
                file_path=resource.file_path,
                line_number=resource.line_number
            )
        return None


class RDSBackupRetentionRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="GRC-RDS-003",
            title="RDS Automated Backup Retention Insufficient (< 7 Days)",
            severity="MEDIUM",
            target_resource="aws_db_instance",
            framework_mappings={
                "CIS_AWS_v3.0": "2.3.2 - RDS Automated Backups",
                "NIST_CSF_2.0": "PR.IR-01 - Disaster recovery resilience",
                "SOC_2_Type_II": "A1.2 - Data availability and recovery",
                "ISO_27001_2022": "A.8.13 - Information Backup"
            },
            description="Backup retention is under 7 days (or 0), failing business continuity and disaster recovery requirements.",
            remediation="Configure 'backup_retention_period' to at least 7 days (recommended 14-30 days)."
        )

    def evaluate(self, resource: TerraformResource, all_resources: List[TerraformResource]) -> Optional[ComplianceFinding]:
        retention = resource.attributes.get("backup_retention_period")
        if retention is None or (isinstance(retention, int) and retention < 7):
            return ComplianceFinding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                resource=resource,
                description=f"RDS instance '{resource.resource_name}' backup retention is {retention} days (minimum 7 required).",
                framework_mappings=self.framework_mappings,
                remediation=self.remediation,
                file_path=resource.file_path,
                line_number=resource.line_number
            )
        return None


ALL_RULES: List[ComplianceRule] = [
    S3ServerSideEncryptionRule(),
    S3PublicAccessBlockRule(),
    S3VersioningRule(),
    SecurityGroupSSHExposureRule(),
    SecurityGroupRDPExposureRule(),
    SecurityGroupDatabaseExposureRule(),
    IAMAdminWildcardRule(),
    IAMStaticAccessKeyRule(),
    RDSEncryptionAtRestRule(),
    RDSPublicAccessRule(),
    RDSBackupRetentionRule(),
]
