# Non-Compliant RDS Instance
# Demonstrates unencrypted storage and public database endpoints

resource "aws_db_instance" "production_db" {
  identifier           = "core-customer-database"
  allocated_storage    = 100
  engine               = "postgres"
  engine_version       = "15.3"
  instance_class       = "db.t3.medium"
  db_name              = "customers"
  username             = "admin"
  password             = "HardcodedPlainTextPassword123!" # VIOLATION: Hardcoded plaintext credentials

  # VIOLATION: Publicly accessible database instance
  publicly_accessible  = true

  # VIOLATION: Storage encryption disabled
  storage_encrypted    = false

  # VIOLATION: Inadequate backup retention (0 days = backups disabled)
  backup_retention_period = 0

  skip_final_snapshot = true
}
