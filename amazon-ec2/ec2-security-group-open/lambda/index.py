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

Security Control: Detective Control for Security Group Rules.
Description:  This Detective Control is used to monitor new Security Group
Rules as they are added to check for an IP Address and CIDR of 0.0.0.0/0 for
and IPv4 and ::/0 for IPv6.

Runtime: Python 3.6
Last Modified: 4/4/2018
"""

import logging
import os
import json
import boto3
from botocore.exceptions import ClientError


def lambda_handler(event, context):
    """Main Lambda hander - evaluates control and makes messaging decisions."""
    setup_logging()
    log.info('Got an event!')
    log.info(json.dumps(event, indent=2))
    cidr_violations = evaluate_control(event)

    if cidr_violations:
        log.info("Sending Violation for:"
                 + str(json.dumps(cidr_violations, indent=2)))
        invoke_alert(event, context, cidr_violations)


def evaluate_control(event):
    """Check to see of CIDR IP Range contains 0.0.0.0/0 or ::/0."""
    log.info('In Evaluate Control')
    cidr_violations = []
    # Check for required event keys.  This is a required step as we have been
    # bitten by checking event keys that do not exist.  If your function does
    # not gracefully exit when it hits a keyError, this is bad.
    try:
        security_group_rules = (event['detail']['requestParameters']
                                ['ipPermissions']['items'])
    except KeyError:
        log.info('Security group rules not found in the event.')
        # Since it's not a violation if security group rules aren't in the
        # event, we return true
        evaluation_status = True
        return evaluation_status, cidr_violations

    # Now loop through each rule and check to see if they have an ipRange
    if "groupId" in event['detail']["requestParameters"]:
        security_group_identifier = (event['detail']["requestParameters"]
                                     ["groupId"])
    elif "groupName" in event['detail']["requestParameters"]:
        security_group_identifier = (event['detail']["requestParameters"]
                                     ["groupName"])
    else:
        log.warning('No VPC Security Group ID or Classic Security Group Name \
Found.')
    for rule in security_group_rules:
        cidr_violations = ipv4_checks(security_group_identifier, rule,
                                      cidr_violations)
        cidr_violations = ipv6_checks(security_group_identifier, rule,
                                      cidr_violations)

    return cidr_violations


def ipv4_checks(security_group_identifier, rule, cidr_violations):
    """IPv4 Checks."""
    try:
        for ipRange in rule['ipRanges']['items']:
            if ipRange['cidrIp'] == '0.0.0.0/0':
                log.info('Violation - Contains IP/CIDR of 0.0.0.0/0')
                cidr_ip = ipRange["cidrIp"]
                create_violation_list(security_group_identifier, rule,
                                      cidr_ip, cidr_violations)

    except KeyError:
        log.warning('There is not any Items under ipRanges')

    return cidr_violations


def ipv6_checks(security_group_identifier, rule, cidr_violations):
    """IPv4 Checks."""
    try:
        for ipv6Range in rule['ipv6Ranges']['items']:
            if ipv6Range['cidrIpv6'] == '::/0':
                log.info('Violation - Contains CIDR IPv6 equal to ::/0')
                cidr_ip = ipv6Range["cidrIpv6"]
                create_violation_list(security_group_identifier, rule,
                                      cidr_ip, cidr_violations)

    except KeyError:
        log.warning('There is not any Items under ipv6Ranges')

    return cidr_violations


def invoke_alert(event, context, cidr_violations):
    """Invoke Alerts and Actions."""
    log.info('In Invoke Alerts')
    subject, message = create_non_compliance_message(event, cidr_violations)
    send_violation(context, subject, message)


def create_violation_list(security_group_identifier,
                          rule, cidr_ip, cidr_violations):
    """Create Violation List."""
    cidr_violations.append({
        "groupIdentifier": security_group_identifier,
        "ipProtocol": rule["ipProtocol"],
        "toPort": rule["toPort"],
        "fromPort": rule["fromPort"],
        "cidrIp": cidr_ip
    })
    return cidr_violations


def create_non_compliance_message(event, cidr_violations):
    """Create Non Compliance Message."""
    log.info("In Create Non Compliance Message")
    subject = "Violation - Security group rule contain a CIDR with /0!"
    message = "Violation - The following Security Group rules were in \
violation of the security group ingress policy and have an ingress rule with \
a CIDR of /0. \n\n"
    for resource in cidr_violations:
        message += 'Security Group Id: ' + resource["groupIdentifier"] + ' \n'
        message += 'IP Protocol: ' + resource["ipProtocol"] + ' \n'
        message += 'To Port: ' + str(resource["toPort"]) + ' \n'
        message += 'From Port: ' + str(resource["fromPort"]) + ' \n'
        message += 'CIDR IP: ' + str(resource["cidrIp"]) + ' \n'
        message += 'Account: ' + event['detail']['userIdentity']["accountId"]
        message += '\nRegion: ' + event['detail']["awsRegion"] + '\n\n\n'

    return subject, message


def send_violation(context, subject, message):
    """Send Violation Message."""
    outbound_topic_arn = os.environ["outbound_topic_arn"]
    findsnsregion = outbound_topic_arn.split(":")
    snsregion = findsnsregion[3]
    sendclient = boto3.client('sns', region_name=snsregion)
    message += "\n\n"
    message += ("This notification was generated by the Lambda function "
                + context.invoked_function_arn)
    try:
        sendclient.publish(
            TopicArn=outbound_topic_arn,
            Message=message,
            Subject=subject
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
