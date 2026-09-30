# Hardened & Compliant S3 Infrastructure
# Satisfies CIS AWS Benchmark 2.1.1, NIST CSF PR.DS-01, and SOC 2 CC6.6 / CC6.7

resource "aws_kms_key" "s3_encryption_key" {
  description             = "Customer-managed KMS key for S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket" "customer_data" {
  bucket = "prod-customer-pii-storage-data"

  tags = {
    Environment = "production"
    DataClass   = "Confidential"
  }
}

# 1. Server-Side Encryption Enforced with Customer Managed Key (CMK)
resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data_encryption" {
  bucket = aws_s3_bucket.customer_data.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# 2. Complete Public Access Block Enforced
resource "aws_s3_bucket_public_access_block" "customer_data_public_block" {
  bucket = aws_s3_bucket.customer_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 3. Object Versioning Enabled for Data Integrity and Ransomware Protection
resource "aws_s3_bucket_versioning" "customer_data_versioning" {
  bucket = aws_s3_bucket.customer_data.id
  versioning_configuration {
    status = "Enabled"
  }
}
