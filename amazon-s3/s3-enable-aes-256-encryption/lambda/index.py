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

Description:  Enables S3 default encryption and set to AES-256 when a user creates a bucket.
Services: Amazon Cloudwatch Events (trigger), AWS Simple Storage Service (S3), AWS Identity and Access Management (IAM)

Runtime: Python 3.6
"""
import logging
import os
import json
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """
    Main Function

    General description of each step this main function is performing
    """
    setup_logging()
    log.info('Lambda received event:')
    log.info(json.dumps(event))

    client = boto3.client('s3')
    bucket_name = event['detail']['requestParameters']['bucketName']
    if "CreateBucket" in event["detail"]["eventName"]:

        client.put_bucket_encryption(
            Bucket = bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                     'ApplyServerSideEncryptionByDefault': {
                         'SSEAlgorithm': 'AES256'
                                                            }
                    }
                        ]
                                                }
                                )
        return True
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
    log.info('Logging setup complete - set to log level ' + str(log.getEffectiveLevel()))
