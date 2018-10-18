Summary
=======

Amazon CloudWatch Events trigger this check when AWS CloudTrail logs Amazon Simple Storage Service **(S3)** API calls. Specifically, CloudWatch Events are triggering on **CreateBucket API call**. The trigger invokes AWS Lambda that runs the Python script provided.

Upon invocation of the above API calls, the newly created bucket will have AES-256 encryption enabled by default and all the objects uploaded to the bucket will be encrypted.

Deployment
==========

To deploy this security control, upload the security control Lambda ZIP file to a location in Amazon S3. This location must be in the same region you intend to deploy the control.

Launch the provided AWS CloudFormation template using the AWS Console and provide the following information:

  | Parameter       | Description
  | --------------- | --------------------------------------------------------------------------------------------------
  | S3 Bucket       | The S3 bucket name you uploaded the Lambda ZIP to
  | S3 Key          | The S3 location of the Lambda ZIP. No leading slashes. (ex. Lambda.zip or controls/lambda.zip. )
  | Logging Level   | Control the verbosity of the logs. INFO should only be used for debug

Caveats
=======

This works only on newly created buckets and not existing buckets. It can take a few seconds after the bucket is created to enable encryption by Lambda. Refresh the console to see the change reflected.
