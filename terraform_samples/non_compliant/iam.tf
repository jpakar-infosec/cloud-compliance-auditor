# Non-Compliant IAM Policies
# Demonstrates violations of Principle of Least Privilege (PoLP)

resource "aws_iam_policy" "admin_wildcard_policy" {
  name        = "overly-permissive-app-policy"
  description = "Allows wide open access across services"

  # VIOLATION: Full admin wildcard on Action and Resource
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowAllActionsEverywhere"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user" "legacy_service_account" {
  name = "legacy-ci-deployer"
}

# VIOLATION: IAM User access key generated directly without secret management or rotation control
resource "aws_iam_access_key" "legacy_key" {
  user = aws_iam_user.legacy_service_account.name
}
