# S3 canary alert example

## What it creates

Terraform creates a uniquely named private S3 bucket, a harmless marker object, encryption and versioning settings, and an EventBridge rule that publishes matching object-read events to an SNS topic. It does not store real credentials or subscribe a recipient to the topic.

## CloudTrail prerequisite

S3 object-level CloudTrail data events must be enabled for the canary bucket for GetObject activity to reach EventBridge. Data events may incur AWS charges. This project does not create or configure an account-wide CloudTrail trail. See the [AWS EventBridge tutorial](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-log-s3-data-events.html). Configure an SNS subscription to receive alerts and confirm delivery in an isolated lab account.

## Safety and cleanup

Review the Terraform plan before applying. Use an isolated AWS account and a unique prefix if you adapt this configuration. The bucket is not configured for force deletion, so remove its object and bucket deliberately after the exercise. The default AWS region is us-east-1.
