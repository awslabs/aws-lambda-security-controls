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

Security Control: All Glacier Data Tagged
Description:  Checks for compliance on activities that could generate violations
  as it relates to Glacier Vaults not having the required tagging as specified
  by the end-user.

Runtime: Python 3.6
"""

import json
import logging
import os
import boto3
from botocore.exceptions import ClientError

OUTBOUND_TOPIC_ARN = os.environ["outbound_topic_arn"]
REQUIRED_KEYS = os.environ["required_keys"].split(",")
GLACIER_CLIENT = boto3.client('glacier')



def lambda_handler(event, context):
    """
    Main handler function.

    sets the Glacier vault that's retrieved from the Cloud Watch events and
    checks if the vault's missing the requisite tag(s)
    """
    setup_logging()
    log.info('Got an event!')
    log.info('e')

    try:
        vault = event["detail"]["requestParameters"]["vaultName"]
    except KeyError:
        log.info('vault not found in the event.')

    try:
        vault_data = GLACIER_CLIENT.list_tags_for_vault(accountId='-',vaultName=vault)
    except ClientError as err:
        print(err)
        return False

    tag_list = []
    for tag in vault_data["Tags"]:
        tag_list.append(tag)

    missing_tag_list = []
    for tag in REQUIRED_KEYS:
        if tag not in tag_list:
            missing_tag_list.append(tag)

    if missing_tag_list:
        subject = "Violation - Glacier Vault is missing tags!"
        message = create_non_compliance_message(
            missing_tag_list, vault, event, context)
        send_violation(OUTBOUND_TOPIC_ARN, message, subject)
    else:
        return None


def send_violation(OUTBOUND_TOPIC_ARN, message, subject):
    """
    SNS function.

    Function that will send the SNS notification
    """
    findsnsregion = OUTBOUND_TOPIC_ARN.split(":")
    snsregion = findsnsregion[3]
    sendclient = boto3.client('sns', region_name=snsregion)
    try:
        sendclient.publish(
            TopicArn=OUTBOUND_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
    except ClientError as err:
        print(err)
        return False


def create_non_compliance_message(missing_tag_list, vault, event, context):
    """
    Messaging function.

    Structures the outgoing SNS notification format
    """
    missing_tags = ', '.join(missing_tag_list)
    message = "Violation - Glacier Vault is missing required tags!  \n\n"
    message += 'Glacier Vault: ' + vault + '\n'
    message += 'Missing Tag(s): ' + missing_tags + '\n'
    message += 'Account: ' + event["account"] + "\n"
    message += "Region: " + event["detail"]["awsRegion"] + "\n"
    message += "\n\n"
    message += "This notification was generated by the Lambda function " + \
        context.invoked_function_arn
    return message


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
    log.info('Logging setup complete - set to log level ' + str(log.getEffectiveLevel()))
