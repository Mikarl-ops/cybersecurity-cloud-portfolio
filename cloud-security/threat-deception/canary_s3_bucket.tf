resource "aws_s3_bucket" "canary_bucket" {
  bucket_prefix = "cybersecurity-canary-"

  tags = {
    Environment = "Deception"
    Security    = "Canary"
  }
}

resource "aws_s3_bucket_public_access_block" "canary_bucket" {
  bucket                  = aws_s3_bucket.canary_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "canary_bucket" {
  bucket = aws_s3_bucket.canary_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "canary_bucket" {
  bucket = aws_s3_bucket.canary_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "canary_file" {
  bucket       = aws_s3_bucket.canary_bucket.id
  key          = "canary-marker.txt"
  content      = "Synthetic canary marker. This object contains no credentials."
  content_type = "text/plain"
}

resource "aws_sns_topic" "canary_alerts" {
  name = "cybersecurity-canary-alerts"
}

resource "aws_cloudwatch_event_rule" "canary_access_trigger" {
  name        = "detect-canary-s3-access"
  description = "Publishes an alert when the canary object is read."

  event_pattern = jsonencode({
    source        = ["aws.s3"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["GetObject"]
      requestParameters = {
        bucketName = [aws_s3_bucket.canary_bucket.bucket]
        key        = [aws_s3_object.canary_file.key]
      }
    }
  })
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.canary_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCanaryRulePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.canary_alerts.arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.canary_access_trigger.arn
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "canary_alerts" {
  rule      = aws_cloudwatch_event_rule.canary_access_trigger.name
  target_id = "canary-alert-topic"
  arn       = aws_sns_topic.canary_alerts.arn

  depends_on = [aws_sns_topic_policy.allow_eventbridge]
}

output "canary_bucket_name" {
  value       = aws_s3_bucket.canary_bucket.bucket
  description = "S3 bucket name for the synthetic canary object."
}

output "canary_alert_topic_arn" {
  value       = aws_sns_topic.canary_alerts.arn
  description = "Subscribe an authorized recipient to receive canary alerts."
}
