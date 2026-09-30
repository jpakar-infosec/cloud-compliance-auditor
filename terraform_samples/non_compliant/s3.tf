# Non-Compliant S3 Infrastructure
# Demonstrates common misconfigurations violating CIS, NIST CSF, and SOC 2

resource "aws_s3_bucket" "customer_data" {
  bucket = "prod-customer-pii-storage-data"

  tags = {
    Environment = "production"
    DataClass   = "Confidential"
  }
}

# VIOLATION: ACL allows public read access
resource "aws_s3_bucket_acl" "customer_data_acl" {
  bucket = aws_s3_bucket.customer_data.id
  acl    = "public-read"
}

# VIOLATION: Missing aws_s3_bucket_server_side_encryption_configuration
# VIOLATION: Missing aws_s3_bucket_public_access_block
# VIOLATION: Missing aws_s3_bucket_versioning

resource "aws_s3_bucket" "app_logs" {
  bucket = "company-raw-access-logs-unencrypted"

  tags = {
    Environment = "staging"
  }
}
