"""
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Security Control: S3 Bucket Policy Enforces Encryption
Description:  Checks for the presence of an S3 bucket policy and verifies that it enforces S3 SSE
via SSE-S3 or SSE-KMS.  Alerts upon violation.

Runtime: Python 3.6
"""

import os
import json
import boto3
from botocore.exceptions import ClientError
import logging

OUTBOUND_TOPIC_ARN = os.environ["outbound_topic_arn"]

def lambda_handler(event, context):
    """
    Main Function.

    1. S3 Put Bucket Policy can fail due to malformed JSON/Resource/Principal and will fail the
    commit.  Ends immediately if there was an error.
    2. check_policy_deleted() is run to validate if the policy was deleted (violation).
    3. check_policy_for_encryption() is run to validate if the policy enforces SSE.
    """
    setup_logging()
    log.info(event)

    print(json.dumps(event))
    policy_check_result = []

    if "errorCode" in event["detail"]:
        log.info("Policy was malformed, PUT was disregarded.  Policy is unchanged.  Ending.")
        return

    if check_policy_deleted(event):
        policy_check_result.append("Violation! S3 Bucket Policy was deleted")
        print('S3 bucket Policy deleted. No S3 Bucket encryption!')
    else:
        print('S3 Bucket Policy exists.  Checking for presence of SSE...')

    if check_policy_for_encryption(event):
         policy_check_result.append("Violation! S3 Bucket Policy is not enforcing SSE")
         print('Violation! S3 Bucket Policy is not enforcing SSE')
    else:
         print('No encryption violation.')

    if policy_check_result:
        message = create_non_compliance_message(
            event, policy_check_result)
        subject = "Violation - S3 Bucket Policy is out of compliance.  No S3 Bucket encryption!"
        send_violation(message, subject, event, context)
    else:
        log.info("No Violations Found!")

def check_policy_deleted(event):
    """Check for S3 Bucket Policy Deletion.  Trigger violation if True."""
    try:
      if "DeleteBucketPolicy" in event["detail"]["eventName"]:
        print("Policy Deleted! No encryption")
        return True
      else:
        return False
    except KeyError as err:
        print(err)
        return False

def check_policy_for_encryption(event):
    """
    Check for encryption in S3 bucket policy.

    Checks the event for a bucket policy PUT.  Loops through and checks for either AES256 or
    AWS:KMS.  Otherwise, trigger a violation.
    """
    try:
        for statement in event["detail"]["requestParameters"]["bucketPolicy"]["Statement"]:
            if statement["Condition"]["StringNotEquals"]["s3:x-amz-server-side-encryption"] == \
            "aws:kms" or statement["Condition"]["StringNotEquals"]\
            ["s3:x-amz-server-side-encryption"] == "AES256":
                print("S3 Bucket Policy uses SSE")
                return False
            else:
                return True
    except KeyError as err:
        print(err)
        return True

def create_non_compliance_message(event, policy_check_result):
    """
    Build A Message.

    Creates a message with a first line stating what this violation is checking
    Creates more lines with identifying information about which specific violations were checked
    This is based upon whether or not the specific violation triggered a "Violation" variable
    Then it adds general information regarding the violation
    """
    message = ""
    for violation in policy_check_result:
        message += violation+"\n"
    message += "S3 Bucket: " + \
        event["detail"]['requestParameters']['bucketName'] + "\n\n"
    return message

def send_violation(message, subject, event, context):
    """
    Send Violation.

    Appends additional information to the message from the Lambda Context
    Sends the message created using an API call to Amazon SNS
    """
    find_sns_region = OUTBOUND_TOPIC_ARN.split(":")
    sns_region = find_sns_region[3]
    message += '\nAccount: ' + event["account"] + "\n"
    message += "Region: " + event["detail"]["awsRegion"] + "\n"
    message += "\n\n"
    message += "This notification was generated by the Lambda function " + \
        context.invoked_function_arn
    send_client = boto3.client('sns', region_name=sns_region)
    try:
        send_client.publish(
            TopicArn=OUTBOUND_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
    except ClientError as err:
        log.info(err)
        return

def setup_logging():
    """
    Logging Function.

    Creates a global log object and sets its level.
    """
    global log
    log = logging.getLogger()
    log_levels = {'INFO': 20, 'WARNING': 30, 'ERROR': 40}

    if 'logging_level' in os.environ:
        log_level = os.environ['logging_level'].upper()
        if log_level in log_levels:
            log.setLevel(log_levels[log_level])
        else:
            log.setLevel(log_levels['ERROR'])
            log.error("The logging_level environment variable is not set to INFO, WARNING, or \
                      ERROR.  The log level is set to ERROR")
    else:
        log.setLevel(log_levels['ERROR'])
        log.warning('The logging_level environment variable is not set. The log level is set to \
                    ERROR')
    log.info('Logging setup complete - set to log level ' +
             str(log.getEffectiveLevel()))
