Summary
=======

Amazon CloudWatch Events trigger this check when AWS CloudTrail logs Amazon EC2 API calls for:

- RunInstances
- AssociateIamInstanceProfile
- ReplaceIamInstanceProfileAssociation

The trigger invokes AWS Lambda and runs the python script provided.

Python Logic
------------

1. Check if the passed Event from CloudWatch has an IAM Instance Profile.

2. If IAM Instance Profile is found:

    a.  Checks IAM Polices documents attached to the IAM Role

        i.  Inline policies

        ii. Managed policies

3. If IAM Profile is not attached to the EC2 instance, it throws violation.

4. If Wildcard Resource or Action is found in the Policy Documents, appends the Policy information to the violations list.

5. Creates a variable with a "Violations" string

6. Check if any variables exist with a "Violations" string.

    b.  If they do, send an AmazonSNS Message to the environment variable topic.

        iii. SNS Message Includes:

            1.  Message line, which indicates if the violation is due to a IAM Instance Profile.

            2.  The Triggering Event Name

            3.  Account Number

            4.  Region

            5.  Lambda Function ARN that invoked the message

Deployment
==========

1. To deploy this security control, upload the security control Lambda ZIP file to a location in Amazon S3. This location must be in the same region you intend to deploy the control.

2. Launch the provided AWS CloudFormation template using the AWS Console and provide the following information:

  | Parameter            | Description
  | -------------------- | --------------------------------------------------------------------------------------------------
  | S3 Bucket            | The S3 bucket name you uploaded the Lambda ZIP to
  | S3 Key               | The S3 location of the Lambda ZIP. No leading slashes. (ex. Lambda.zip or controls/lambda.zip. )
  | Notification Email   | An email address where you would like violation notifications sent
  | Logging Level        | Control the verbosity of the logs. INFO should only be used for debug

Caveats
=======

The Current version of the code works with the following Caveats:

- Detaching IAM Profile is not monitored by this detective control since it is not part of the scope of the control.

- Does not check for modification of IAM Policies that are attached to the EC2 IAM Profile.

- Does not account for Unsupported Resource-Level Permissions that required the use of \"Resource: \*\"
  - <http://docs.aws.amazon.com/AWSEC2/latest/APIReference/ec2-api-permissions.html#ec2-api-unsupported-resource-permissions>