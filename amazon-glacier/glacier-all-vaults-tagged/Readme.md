Summary
=======

This security control checks that all Amazon Glacier data is tagged with a list of required user set values. Amazon CloudWatch Events trigger this check when AWS CloudTrail logs Glacier API calls.

Specifically, CloudWatch Events is triggering on **AddTagsToVault, RemoveTagsFromVault** and **UploadArchive**. The trigger invokes AWS Lambda which runs the Python script attached. The python script will take in the CloudWatch event and perform a ListTagsForVault API call. It will then evaluate the list of tags associated with the Glacier vault compared to what the required tags are, which are specified in the AWS CloudFormation template. For any tags that are non-existent, the python script will send an SNS notification.

Deployment
==========

To deploy this security control, upload the security control Lambda ZIP file to a location in Amazon S3. This location must be in the same region you intend to deploy the control.

Launch the provided CloudFormation template using the AWS Console and provide the following information:

  | Parameter            | Description
  | -------------------- | --------------------------------------------------------------------------------------------------
  | S3 Bucket            | The S3 bucket name you uploaded the Lambda ZIP to
  | S3 Key               | The S3 location of the Lambda ZIP. No leading slashes. (ex. Lambda.zip or controls/lambda.zip. )
  | Notification Email   | An email address where you would like violation notifications sent
  | Logging Level        | Control the verbosity of the logs. INFO should only be used for debug
  | Required Keys        | Tag keys that are required on Glacier vaults.

Caveats
=======

The Lambda function will only invoke on existing Glacier vaults when tags are added and/or removed or when a new object is uploaded to the Glacier Vault. The API calls for creating a Glacier vault doesn't allow you to specify tags during its creation. Once an archive is loaded to the Glacier vault, will it then invoke the Lambda function to determine if the Glacier Vault has the requisite tags associated with it.
