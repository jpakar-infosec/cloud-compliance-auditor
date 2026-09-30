# Hardened & Compliant Security Groups
# Satisfies CIS AWS Benchmark 5.2, 5.3, and NIST CSF PR.AC-05

resource "aws_security_group" "bastion_ingress_compliant" {
  name        = "bastion-host-sg-hardened"
  description = "Security group for bastion host with restricted access"
  vpc_id      = "vpc-12345678"

  # COMPLIANT: SSH access restricted strictly to corporate VPN / IP CIDR
  ingress {
    description = "SSH access restricted to corporate VPN"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.50.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = "production"
    Hardened    = "true"
  }
}

resource "aws_security_group" "database_sg_compliant" {
  name        = "production-db-sg-hardened"
  description = "Database Security Group - Internal App Tier Only"
  vpc_id      = "vpc-12345678"

  # COMPLIANT: Database port restricted to application private subnet CIDR
  ingress {
    description = "Postgres access restricted to private App Tier"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.10.0/24"]
  }
}
