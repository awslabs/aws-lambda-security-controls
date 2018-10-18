Summary
=======

In order for the controls to monitor Amazon Simple Storage Service (Amazon S3) Object-Level actions like s3:PutObject, there is an additional step which includes configuring Amazon CloudTrail Data Events. These Data Events are object-level API operations that access Amazon S3 buckets. By default, trails don't log data events and they must be configured for each bucket you wish to monitor. This configuration is global.

The AWS Lambda function check is run when a relevant (s3:PutObject, s3:CopyObject) S3 API call is seen. The check looks for AWS Key Management Service (AWS KMS) related data and customer Algorithm related data in CloudTrail Logs. If any AWS KMS data is found it will alert the Amazon Simple Notification Service (Amazon SNS) topic. If the customer algorithm is not found for Server-Side Encryption, it will also alert.

Deployment
==========

To deploy this security control, upload the security control Lambda ZIP file to a location in Amazon S3. This location must be in the same region you intend to deploy the control.

Additionally, your CloudTrail will need to be set up for S3 object level logging. This can be done by adding in S3 bucket in the AWS CloudTrail console.

Launch the provided AWS CloudFormation template using the AWS Console and provide the following information:

  | Parameter            | Description
  | -------------------- | --------------------------------------------------------------------------------------------------
  | S3 Bucket            | The S3 bucket name you uploaded the Lambda ZIP to
  | S3 Key               | The S3 location of the Lambda ZIP. No leading slashes. (ex. Lambda.zip or controls/lambda.zip. )
  | Notification Email   | An email address where you would like violation notifications sent
  | Logging Level        | Control the verbosity of the logs. INFO should only be used for debug

Caveats
=======

S3 Encryption Controls must be deployed regionally. You must follow the procedure in "Deployment" for every region that has resources to be monitored.

In order for the controls to monitor S3 Object-Level actions like s3:PutObject, there is an additional step which includes configuring CloudTrail Data Events. These Data Events are object-level API operations that access Amazon S3 buckets. By default, trails don't log data events and they must be configured for each bucket you wish to monitor. This configuration is global.
