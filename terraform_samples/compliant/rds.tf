# Hardened & Compliant RDS Instance
# Satisfies CIS AWS Benchmark 2.3.1, NIST CSF PR.DS-01, and SOC 2 CC6.6

resource "aws_kms_key" "rds_encryption_key" {
  description         = "KMS key for RDS storage encryption"
  enable_key_rotation = true
}

resource "aws_db_instance" "production_db_compliant" {
  identifier           = "core-customer-database-secure"
  allocated_storage    = 100
  engine               = "postgres"
  engine_version       = "15.3"
  instance_class       = "db.t3.medium"
  db_name              = "customers"

  # COMPLIANT: Credentials managed via AWS Secrets Manager (referenced via data source / dynamic injection)
  manage_master_user_password = true

  # COMPLIANT: Isolated from public internet
  publicly_accessible  = false

  # COMPLIANT: Storage encrypted at rest using KMS
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.rds_encryption_key.arn

  # COMPLIANT: Multi-day automated backup retention enabled
  backup_retention_period = 30
  backup_window           = "03:00-04:00"

  # COMPLIANT: Multi-AZ high availability & deletion protection enabled
  multi_az            = true
  deletion_protection = true

  tags = {
    Environment = "production"
    DataClass   = "Confidential"
  }
}
