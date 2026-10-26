# Example S3 policy requiring secure transport

This bucket-policy example denies S3 requests to the named bucket when aws:SecureTransport is false. It is a policy template only; it is not attached to an AWS account or bucket by this repository. Replace the example ARN with an authorized resource and validate the effect against the account's access model before use.
