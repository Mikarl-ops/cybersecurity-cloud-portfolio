variable "aws_region" {
  type        = string
  description = "The target deployment region."
  default     = "us-east-1"
}

variable "corporate_ip_range" {
  type        = string
  description = "Trusted corporate office external CIDR block for firewall validation."
  default     = "192.0.2.0/24" # Test placeholder netblock
}