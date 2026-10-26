terraform {
  required_version = ">= 1.5.0"

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

resource "aws_vpc" "secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "Portfolio-Secure-VPC"
    Environment = "Lab"
    ManagedBy   = "Terraform"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = format("%sa", var.aws_region)

  tags = {
    Name = "Portfolio-Private-Subnet"
  }
}

resource "aws_security_group" "hardened_sg" {
  name        = "portfolio-web-ingress-filter"
  description = "Example HTTPS ingress restriction for a future workload."
  vpc_id      = aws_vpc.secure_vpc.id

  ingress {
    description = "HTTPS from the configured trusted CIDR"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.corporate_ip_range]
  }

  egress {
    description = "HTTPS egress example"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Portfolio-Hardened-Web-Firewall"
  }
}

output "vpc_id" {
  value       = aws_vpc.secure_vpc.id
  description = "ID of the example VPC."
}

output "private_subnet_id" {
  value       = aws_subnet.private_subnet.id
  description = "ID of the subnet with no internet-gateway route configured."
}
