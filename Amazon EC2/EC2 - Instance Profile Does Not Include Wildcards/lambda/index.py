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

Information Block

Amazon EC2 IAM Role Security Certification
Checks for compliance on activities that could generate violations
Checks Amazon EC2 Launch and IAM Instance Profile Events and reports Policies
with WildCard in Action or Resources.
API Triggers: RunInstances, AssociateIamInstanceProfile,
ReplaceIamInstanceProfileAssociation
Services: CloudWatch Events (trigger), SNS, IAM

"""

import os
import logging
import json
import boto3
from botocore.exceptions import ClientError

OUTBOUND_TOPIC_ARN = os.environ["outbound_topic_arn"]


def lambda_handler(event, context):
    """
    Main function: Checks if EC2 Instance is launched with IAM Profile.

    If no IAM Profile found, throws violation.
    If IAM Profile found, checks polices attached to the role.
    If finds wildcard in resource or action in the policy document, throws
    violation.
    """
    setup_logging()
    log.info('Lambda received event:')
    log.info(json.dumps(event))
    violations = []
    ec2instancename = find_ec2(event)
    try:
        instanceprofile = find_rolename(event)
    except Exception as e:
        log.info("Exception thrown: %s" % str(e))
        instanceprofile = ''
        pass
    if instanceprofile:
        check_profile_policy(event, ec2instancename, instanceprofile,
                             violations)
    else:
        violations.append("No Instance Profile Found in EC2 Instance: "
                          + ec2instancename + " in the Event: "
                          + event["detail"]["eventName"])
        # log.info (violations)
    if violations:
        message = create_non_compliance_message(violations)
        subject = "Violation - EC2 IAM Profile is out of compliance!"
        send_violation(message, subject, event, context)
    else:
        log.info("No Violations Found!")
    return violations


def find_rolename(event):
    """Function to find IAM Role."""
    if event["detail"]["eventName"] == "AssociateIamInstanceProfile":
        rolename = event["detail"]["requestParameters"]["AssociateIamInstanceProfileRequest"]["IamInstanceProfile"]["Name"]
    if event["detail"]["eventName"] == "ReplaceIamInstanceProfileAssociation":
        rolename = event["detail"]["requestParameters"]["ReplaceIamInstanceProfileAssociationRequest"]["IamInstanceProfile"]["Name"]
    if event["detail"]["eventName"] == "RunInstances" and "iamInstanceProfile" in event["detail"]["requestParameters"]:
        rolename = event["detail"]["requestParameters"]["iamInstanceProfile"]["arn"].split('/')[1]
    return rolename


def find_ec2(event):
    """Function to find EC2 Instance ID."""
    if event["detail"]["eventName"] == "AssociateIamInstanceProfile":
        ec2instance = event["detail"]["requestParameters"]["AssociateIamInstanceProfileRequest"]["InstanceId"]
    if event["detail"]["eventName"] == "ReplaceIamInstanceProfileAssociation":
        ec2instance = event["detail"]["responseElements"]["ReplaceIamInstanceProfileAssociationResponse"]["iamInstanceProfileAssociation"]["instanceId"]
    if event["detail"]["eventName"] == "RunInstances":
        ec2instance = event["detail"]["responseElements"]["instancesSet"]["items"][0]["instanceId"]
    return ec2instance


def check_profile_policy(event, ec2instancename, instanceprofile, violations):
    """
    Function to list managed and inline policies attached to the IAM Role.

    If function finds WildCard in Resources or Actions, then appends to the
    violations list.
    """
    client = boto3.client('iam')
    role1 = client.list_role_policies(RoleName=instanceprofile)
    role2 = client.list_attached_role_policies(RoleName=instanceprofile)
    inlinepolicylist = []
    inlinepolicylist = role1["PolicyNames"]
    # log.info(inlinepolicylist)
    for names in inlinepolicylist:
        policydetail1 = client.get_role_policy(RoleName=instanceprofile,
                                               PolicyName=names)
        # log.info(policydetail1)
        for item in policydetail1["PolicyDocument"]["Statement"]:
            # log.info (item["Resource"])
            # log.info (item["Action"])
            if item["Resource"] == ['*']:
                violations.append("EC2 IAM Profile: " + instanceprofile + "\n"
                                  + "Event: " + event["detail"]["eventName"]
                                  + "\n" + "EC2 Instance:" + ec2instancename
                                  + "\n" + "Inline Policy: " + names + "\n"
                                  + "Violation: WildCard Resource" + "\n")
            if item["Action"] == ['*']:
                violations.append("EC2 IAM Profile: " + instanceprofile + "\n"
                                  + "Event: " + event["detail"]["eventName"]
                                  + "\n" + "EC2 Instance:" + ec2instancename
                                  + "\n" + "Inline Policy: " + names + "\n"
                                  + "Violation: WildCard Action" + "\n")
            # log.info(violations)
    for policy in role2["AttachedPolicies"]:
        # policy_list.append(policy["PolicyName"])
        policyversion = client.get_policy(PolicyArn=policy["PolicyArn"])
        policy_detail = client.get_policy_version(
            PolicyArn=policy["PolicyArn"],
            VersionId=policyversion["Policy"]["DefaultVersionId"])
        # log.info (policyversion)
        log.info(policy_detail)
        for item1 in policy_detail["PolicyVersion"]["Document"]["Statement"]:
            if item1["Resource"] == "*":
                violations.append("EC2 IAM Profile: " + instanceprofile + "\n"
                                  + "Event: " + event["detail"]["eventName"]
                                  + "\n" + "EC2 Instance:" + ec2instancename
                                  + "\n" + "Managed Policy: "
                                  + policy["PolicyName"] + "\n"
                                  + "Violation: WildCard Resource" + "\n")
            if item1["Action"] == "*":
                violations.append("EC2 IAM Profile: " + instanceprofile + "\n"
                                  + "Event: " + event["detail"]["eventName"]
                                  + "\n" + "EC2 Instance:" + ec2instancename
                                  + "\n" + "Managed Policy: "
                                  + policy["PolicyName"] + "\n"
                                  + "Violation: WildCard Action" + "\n")
    return violations


def create_non_compliance_message(violations):
    """Create the Non Compliance Message."""
    message = "Violation - The following EC2 IAM Role is in violation of security compliance \n\n"
    for violation in violations:
        message += violation + "\n"
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
    log.info('Logging setup complete - set to log level ' + str(log.getEffectiveLevel()))
