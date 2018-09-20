Summary
=======

This security controls checks that EC2 instances that are created are only launched in approved Regions. During the template launch a set of approved regions can be declared. Amazon CloudWatch Events trigger this check when CloudTrail logs **EC2** API calls. Specifically, Amazon CloudWatch Events is triggering on **ModifyInstanceAttiribute** and **RunInstances**. The trigger invokes Lambda which runs the python script attached. The python script will take in the Amazon CloudWatch event of the aforementioned API calls and compare the region given with that of the region list passed in as an Amazon CloudFormation parameter. If the instance is launched in a region outside of the list, the python script will trigger an SNS notification detailing the instance ID, account number, region along with the Lambda function ARN.

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

Caveats
=======

The AWS CloudWatch Event Rule must be created in each region you wish to trigger the function from. The Event Rule must also have an associated Lambda Function in that same region. The Lambda Function Role must have permission to Lambda:GetPolicy and SNS:Publish.

The AWS CloudWatch Event Rules are using EventNames that may change in the future for new events.
