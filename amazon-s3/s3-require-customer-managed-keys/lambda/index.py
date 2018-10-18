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
"""

import logging
import os
import json
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """Main Lambda hander - evaluates control and makes messaging decisions."""
    print(json.dumps(event))
    setup_logging()
    log.info('Got an event!')
    log.info(event['detail']['eventName'])
    bucket_name = event['detail']['requestParameters']['bucketName']
    key = event['detail']['requestParameters']['key']
    message = ''

    #If kms_key_exists is false and sse_customer_algorithm_exists is true
    if kms_key_exists(event):
        message = "Violation - S3://" + bucket_name + "/" + key + " is using a KMS Key for Encryption \n"
    if not sse_customer_algorithm_exists(event):
        message += "Violation - S3://" + bucket_name + "/" + key + " is not using SSE Customer Algorithm for Encryption \n"
    if message:
        log.info('Invoking and Alert.')
        send_violation(message)
    else:
        log.info('No KMS Key used and SSE Customer Algorithm was found. No violations.')

def kms_key_exists(event):
    """Key exist function - check for KMS Key ID"""
    if 'x-amz-server-side-encryption-aws-kms-key-id' in event['detail']['responseElements']:
        return True
    return False

def sse_customer_algorithm_exists(event):
    """Algorithm function - check for customer algorithm"""
    if 'x-amz-server-side-encryption-customer-algorithm' in event['detail']['responseElements']:
        return True
    return False

#Function to send SNS Message
def send_violation(message):
    findsnsregion = os.environ['outbound_topic_arn'].split(":")
    snsregion = findsnsregion[3]
    sendclient = boto3.client('sns', region_name=snsregion)
    try:
        sendclient.publish(
            TopicArn=os.environ['outbound_topic_arn'],
            Message=message,
            Subject='S3 Encryption Violation Detected'
        )
    except ClientError as err:
        print(err)
        return False

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
    log.info('Logging setup complete - set to log level '
             + str(log.getEffectiveLevel()))