# Non-Compliant Security Groups
# Demonstrates direct exposure of administrative & database ports to 0.0.0.0/0

resource "aws_security_group" "bastion_ingress" {
  name        = "bastion-host-sg"
  description = "Security group for bastion host"
  vpc_id      = "vpc-12345678"

  # VIOLATION: SSH (Port 22) open to the entire internet
  ingress {
    description = "SSH access from anywhere (Violation: CIS AWS 5.2)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VIOLATION: RDP (Port 3389) open to the entire internet
  ingress {
    description = "Windows RDP access from anywhere (Violation: CIS AWS 5.3)"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "database_sg" {
  name        = "production-db-sg"
  description = "Database Security Group"
  vpc_id      = "vpc-12345678"

  # VIOLATION: Database port (PostgreSQL 5432) exposed to 0.0.0.0/0
  ingress {
    description = "Direct Postgres access (Violation: NIST PR.AC-05)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
