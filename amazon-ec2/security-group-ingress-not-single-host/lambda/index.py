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

Checks whether an Ingress Security Group Rule allows a /32 network in IPv4 or IPv6.
If a /32 ingress rule is created, the function returns False.
API Triggers: ec2 AuthorizeSecurityGroupIngress
Services: Cloudwatch Events (trigger)
"""

import os
import boto3
import json
import logging
from botocore.exceptions import ClientError

OUTBOUND_TOPIC_ARN = os.environ["outbound_topic_arn"]


def lambda_handler(event, context):
    # Configure Lambda Logging.
    setup_logging()
    try:
        logging.info(json.dumps(event))
        security_group_ingress_info = get_security_group_ingress_info(event)
        # Get all ingress CIDR rules to evaluate from the security group
        for security_group_info in security_group_ingress_info:
            cidr_violations = []
            # Check IPV4
            if "items" in security_group_info["ipRanges"]:
                for ip_range in security_group_info["ipRanges"]["items"]:
                    if is_netmask_slash_32_or_128(ip_range["cidrIp"]):
                        cidr_violations.append({
                            "groupIdentifier": security_group_info["groupIdentifier"],
                            "ipProtocol": security_group_info["ipProtocol"],
                            "toPort": security_group_info["toPort"],
                            "fromPort": security_group_info["fromPort"],
                            "cidrIp": ip_range["cidrIp"]
                        })
            # Check IPv6
            if "items" in security_group_info["ipv6Ranges"]:
                for ip_range in security_group_info["ipv6Ranges"]["items"]:
                    if is_netmask_slash_32_or_128(ip_range["cidrIpv6"]):
                        cidr_violations.append({
                            "groupIdentifier": security_group_info["groupIdentifier"],
                            "ipProtocol": security_group_info["ipProtocol"],
                            "toPort": security_group_info["toPort"],
                            "fromPort": security_group_info["fromPort"],
                            "cidrIp": ip_range["cidrIpv6"]
                        })
            if cidr_violations:
                subject = "Violation - Security group does not meet the Cidr policy!"
                logging.warning('CIDR Violation')
                send_violation(OUTBOUND_TOPIC_ARN,
                               cidr_violations, subject, event, context)
                return False
            else:
                logging.info('No CIDR Violation')
                return True
    except KeyError:
        security_group_ingress_info = False
        logging.warning(
            'Key Error has occurred, this function has fail-closed')
        return security_group_ingress_info

# Checks the event to see if a groupname is specified or a group id


def get_security_group_ingress_info(event):
    security_group_identifier = ""
    security_group_ingress_info = []
    if "groupId" in event["detail"]["requestParameters"]:
        security_group_identifier = event["detail"]["requestParameters"]["groupId"]
    elif "groupName" in event["detail"]["requestParameters"]:
        security_group_identifier = event["detail"]["requestParameters"]["groupName"]
    for item in event["detail"]["requestParameters"]["ipPermissions"]["items"]:
        if "ipRanges" in item:
            security_group_ingress_info.append({
                "groupIdentifier": security_group_identifier,
                "ipProtocol": item["ipProtocol"],
                "toPort": str(item["toPort"]),
                "fromPort": str(item["fromPort"]),
                "ipRanges": item["ipRanges"],
                "ipv6Ranges": item["ipv6Ranges"]
            })
    return security_group_ingress_info

# Checks to see if the netmask of a cidr block is /0


def is_netmask_slash_32_or_128(cidr_block):
    cidr_netmask_start = cidr_block.find("/")
    cidr_netmask_end = cidr_netmask_start - len(cidr_block)
    netmask = cidr_block[cidr_netmask_end:]
    if netmask == "/32":
        return True
    elif netmask == "/128":
        return True
    return False

# Send SNS Notification


def send_violation(outbound_topic_arn, message, subject, event, context):
    findsnsregion = outbound_topic_arn.split(":")
    snsregion = findsnsregion[3]
    message += '\nAccount: ' + event["account"] + "\n"
    message += "Region: " + event["detail"]["awsRegion"] + "\n"
    message += "\n\n"
    message += "This notification was generated by the Lambda function " + \
        context.invoked_function_arn
    sendclient = boto3.client('sns', region_name=snsregion)
    try:
        sendclient.publish(
            TopicArn=outbound_topic_arn,
            Message=message,
            Subject=subject
        )
    except ClientError as err:
        print(err)
        return False

# Setup logging for this function


def setup_logging():
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
