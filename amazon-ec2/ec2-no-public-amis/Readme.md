Summary
=======

Amazon CloudWatch Events trigger this check when AWS CloudTrail logs **Amazon Elastic Compute Cloud (Amazon EC2)** API calls. Specifically, CloudWatch Events are triggering on **ModifyImageAttribute.** The trigger invokes AWS Lambda that runs the Python script provided.

The AWS Lambda function will evaluate for each respective event and call its own respective function. When an Amazon EC2 AMI is made public, it will trigger a violation which will compose and send a violation message using Amazon Simple Notification Service (SNS) to the provided topic. The Lambda function, once it has identified the Amazon EC2 AMI ID it will call the **ResetImageAttribute** API call to set the AMI ID back to its default permissions -- private.

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

This detective control must be deployed in the region you intend to monitor.

Additionally, this Lambda function will error check. Logic has been included to ignore any events that are come across. For instance, attempting to make an Amazon EC2 AMI public that's encrypted will result in a failure.
