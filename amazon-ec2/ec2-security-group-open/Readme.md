Summary
========
Amazon CloudWatch Events trigger this check when AWS CloudTrail logs EC2 API calls. Specifically, Amazon CloudWatch Events Rules monitoring AWS CloudTrail Logs, trigger based on an API call for "AuthorizeSecurityGroupIngress". The trigger invokes AWS Lambda which runs the python script attached. The python script evaluates the Source IP Address and CIDR range. If the CIDR range is 0.0.0.0/0 for IPv4, or ::/0 for IPv6, the Lambda function will send a violation notification.

Deployment
==========

To deploy this security control, upload the security control Lambda ZIP file to a location in Amazon S3. This location must be in the same region you intend to deploy the control.

Launch the provided AWS CloudFormation template using the AWS Console and provide the following information:

  | Parameter            | Description
  | -------------------- | --------------------------------------------------------------------------------------------------
  | S3 Bucket            | The S3 bucket name you uploaded the Lambda ZIP to
  | S3 Key               | The S3 location of the Lambda ZIP. No leading slashes. (ex. Lambda.zip or controls/lambda.zip. )
  | Notification Email   | An email address where you would like violation notifications sent
  | Logging Level        | Control the verbosity of the logs. INFO should only be used for debug