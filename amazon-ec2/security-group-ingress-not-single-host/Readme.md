Summary
=======

This security control is designed to notify stakeholders when AWS resources do not meet the standard set forth by customer specifications. This control looks for single host network entries for both IPv4 and IPv6 security group source address fields.

CloudWatch Events trigger this check when CloudTrail logs EC2 API calls. Specifically, CloudWatch Events is triggering on AuthorizeSecurityGroupIngress. The trigger invokes Lambda which runs the python script attached. The python script evaluates the net mask of the Cidr block. If the net mask is determined to be anything other than /32 or /128 (IPv6) the Lambda function will send a violation notification.

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

