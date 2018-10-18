Summary
=======

Amazon CloudWatch Events trigger this check when AWS CloudTrail logs **Amazon Simple Storage Service** API calls. Specifically, CloudWatch Events are triggering on **PutBucketPolicy**, and **DeleteBucketPolicy**. The trigger invokes AWS Lambda that runs the python script provided.

When a DeleteBucketPolicy API call is encountered, this indicates a policy is not in place and constitutes a violation of this security control. This immediately causes an alert.

When a PutBucketPolicy API call is encountered, Lambda evaluates the body of the request for the policy statements, looping through each one looking for `"StringNotEquals\": { "s3:x-amz-server-side-encryption": "aws:kms" or "AES256" }`. If neither is found, a Violation is triggered.

PutBucketPolicy will also be triggered if a malformed policy is submitted to S3. However, S3 rejects the policy as malformed and discards the PUT. Lambda has handling for this and will immediately halt execution of all checks if S3 noted that the policy wasn't actually applied to the bucket due to malformed syntax.

Deployment
==========

To deploy this security control, upload the security control Lambda ZIP file to a location in Amazon S3. This location must be in the same region you intend to deploy the control.

Launch the provided AWS CloudFormation template using the AWS Console and provide the following information:

  | Parameter            | Description
  | -------------------- | --------------------------------------------------------------------------------------------------
  | S3 Bucket            | The S3 bucket name you uploaded the Lambda ZIP to
  | S3 Key               | The S3 location of the Lambda ZIP. No leading slashes. (ex. Lambda.zip or controls/lambda.zip. )
  | Notification Email   | An email address where you would like violation notifications sent
  | Logging Level        | Control the verbosity of the logs. INFO should only be used for debugging

Caveats
=======

This detective control is regional and must be deployed in the regions you intend to monitor.

This control looks for the presence of the "aws:kms" or "AES256" encryption strings, but not the context in which it they are used. There is potential to work around the intended control by reducing the scope in the Resource key.

For example:
```
{
  "Sid": "DenyUnEncryptedObjectUploads",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::ohiobucket/ohiofolder/ohiofolder",
  "Condition": {
    "StringNotEquals": {
      "s3:x-amz-server-side-encryption": "aws:kms"
    }
  }
}

```
...would only protect the ohiobucket/ohiofolder/ohiofolder scope leaving you able to upload files unencrypted to the remainder of the bucket.
