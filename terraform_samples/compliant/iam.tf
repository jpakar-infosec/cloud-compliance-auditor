# Hardened & Compliant IAM Policies
# Satisfies CIS AWS Benchmark 1.16, NIST PR.AC-04, and SOC 2 CC6.1 / CC6.2

resource "aws_iam_policy" "scoped_app_policy" {
  name        = "scoped-customer-data-reader"
  description = "Principle of least privilege policy for customer data access"

  # COMPLIANT: Explicit granular permissions scoped to exact resource ARN
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSpecificBucketActions"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::prod-customer-pii-storage-data",
          "arn:aws:s3:::prod-customer-pii-storage-data/*"
        ]
      }
    ]
  })
}

# COMPLIANT: Use IAM Roles with OIDC or AssumeRole instead of long-lived static Access Keys
resource "aws_iam_role" "ci_deployer_role" {
  name = "github-actions-deployer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
      }
    ]
  })
}
