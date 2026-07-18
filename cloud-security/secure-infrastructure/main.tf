# ==============================================================================
# Filename: main.tf
# Description: Terraform configuration deploying a secure, architecture-hardened
#              VPC infrastructure baseline.
# ==============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# 1. Provision the primary isolated VPC
resource "aws_vpc" "secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "Production-Secure-VPC"
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}

# 2. Establish an isolated Private Subnet (No direct Internet exposure)
resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "Isolated-Database-Tier"
  }
}

# 3. Provision a hardened Security Group (Perimeter Firewall)
resource "aws_security_group" "hardened_sg" {
  name        = "secure-web-ingress-filter"
  description = "Enforce strict ingress filters; deny all except corporate HTTPS traffic."
  vpc_id      = aws_vpc.secure_vpc.id

  # Inbound: Allow HTTPS (TLS 1.3/1.2) ONLY from corporate trusted IP block
  ingress {
    description = "Allow inbound HTTPS from Corporate Office"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.corporate_ip_range]
  }

  # Outbound: Enforce restriction on outbound web traffic (Patching/Updates only)
  egress {
    description = "Allow secure outbound web traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Hardened-Web-Firewall-Policy"
  }
}