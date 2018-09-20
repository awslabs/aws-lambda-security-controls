Summary
=======

This security control monitors the creation of Auto Scaling groups, and ensures an instance profile is present.

CloudWatch Events trigger this check when CloudTrail logs **Auto Scaling** API calls. Specifically, CloudWatch Events is triggering on **CreateLaunchConfiguartion**. The trigger invokes Lambda which runs the Python script attached. The Python script will analyze CloudWatch events for when an Auto Scaling Launch Configuration is created. In the creation stage, the launch configuration can be provided an IAM instance profile. When a launch configuration is created with an IAM profile, the response will return a JSON body back with an "iamInstanceProfile" response. In this event, the function will do nothing. However, when a launch configuration is created without an IAM profile, the Python script will determine that the aforementioned response is missing and will send an SNS notification detailing the launch configuration name, region and account along with the Lambda ARN that this is notification is sourced from.

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

Since this is an event-based alert, this function will only notify via SNS for new subsequent launch configurations that are created, not existing ones given that the CreateLaunchConfiguration call is the only one that includes the iamInstanceProfile string in its JSON response.
