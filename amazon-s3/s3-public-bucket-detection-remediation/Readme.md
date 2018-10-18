Summary
================

CloudWatch Events trigger this check when CloudTrail logs the **Amazon Simple Storage Service (Amazon S3)** API call **"PutBucketAcl"**.

The trigger invokes AWS Lambda which runs the Python script attached. The Python script describes the current bucket ACL, and if AllUsers or AuthenticatedUsers is found in the current policy it attempts to overwrite the ACL with "private". If LogDelivery permissions are found, it will retain those permissions while attempting to remove the public ACL entries.

Once complete, the Lambda function will send a violation notification to the Amazon Simple Notification Service (Amazon SNS) and ultimately, the email subscriber defined during the AWS CloudFormation stack creation.

Deployment
============

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

The Lambda Function is regional, so it will need to be launched in each region that has Amazon S3 buckets to be monitored.
