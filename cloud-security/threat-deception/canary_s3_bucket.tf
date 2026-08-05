# ==============================================================================
# File: canary_s3_bucket.tf
# Description: Terraform configuration deploying an S3 "Canary Bucket" (Honeytoken)
#              designed to trigger an alert if accessed by an attacker.
# ==============================================================================

resource "aws_s3_bucket" "canary_bucket" {
  bucket        = "corp-confidential-passwords-canary"
  force_destroy = true

  tags = {
    Environment = "Deception"
    Security    = "Honeytoken"
  }
}

# Object placed as bait inside the canary bucket
resource "aws_s3_object" "canary_file" {
  bucket  = aws_s3_bucket.canary_bucket.id
  key     = "db_credentials_backup.csv"
  content = "username,password\nadmin,SuperSecretPass123!\n"
}

# EventBridge Rule to capture any GetObject API calls on the canary asset
resource "aws_cloudwatch_event_rule" "canary_access_trigger" {
  name        = "detect-canary-s3-access"
  description = "Triggers high-priority security alert if canary file is accessed."

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-name = ["ViaEnhancedMonitoring"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["GetObject"]
      resources = {
        ARN = ["${aws_s3_bucket.canary_bucket.arn}/db_credentials_backup.csv"]
      }
    }
  })
}