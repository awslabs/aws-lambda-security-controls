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

Security Control: Revert public ACLs on Amazon S3 buckets
Description:  Automated detection and remediation of public Amazon S3 buckets.
    The intention is to check at the ACL level of the bucket and if
    ACL=='public-read'||'public-read-write'||'authenticated-read'
    then set it back to 'private'
Runtime: Python 3.6
"""

import logging
import os
import json
import boto3
from botocore.exceptions import ClientError

S3_RESOURCE = boto3.resource('s3')

def lambda_handler(event, context):
    """Main Lambda hander - evaluates control and makes messaging decisions."""
    setup_logging()
    log.info('Got an event!')
    log.info(json.dumps(event, indent=2))
    # Check for required event keys.  This will allow the function to gracefully
    # exit if an expected Key is not present.
    try:
        bucket_name = event['detail']['requestParameters']['bucketName']
    except KeyError:
        s3_violations = 'Bucket name not found in event. Can not proceed with check. Manual followup recommended' 
        log.info(s3_violations)
        # Since we can't react to this event without a bucket name
        # in this, we return true to notify stakeholders to intervene
        return False, s3_violations

    passing, s3_violations = evaluate_control(bucket_name, event)

    if passing == False:
        invoke_alert(event, context, s3_violations)

def evaluate_control(bucket_name, event):
    """Check to see bucket ACL is currently anything other than Private"""
    log.info('Evaluating Access Control List')
    s3_violations = []
    #Immediately return True if the triggering ACL operation was a change to Private
    if 'x-amz-acl' in event['detail']['requestParameters']:
        log.info('ACL is currently "' + event['detail']['requestParameters']['x-amz-acl'][0] + '"')
        if event['detail']['requestParameters']['x-amz-acl'][0] == "private":
            log.info('ACL is already private.  Ending.')
            return True, s3_violations
    #Immediately return True if the triggering ACL encountered an error before completion (loop protection)
    if 'errorCode' in event['detail']:
        log.info('Lambda was invoked on an API call that resulted in an error.  Ending')
        return True, s3_violations
    if 'errorMessage' in event['detail']:
        log.info('Lambda was invoked on an API call that resulted in an error.  Ending')
        return True, s3_violations

    try:
        log.info("Describing the current ACL")
        bucket_acl = S3_RESOURCE.BucketAcl(bucket_name)
    except Exception as err:
        s3_violations.append('Unable to describe the bucket ACL.  Error was: ' + err + ' Manual followup recommended')
        log.info(s3_violations)
        # Since we can't react to this event without a bucket name provided
        # We return false to notify stakeholders to intervene
        return False, s3_violations
    #Determine if "AllUsers" or "AuthenticatedUsers" are present
    uri_list = ""
    preserve_log_delivery = []
    for grant in bucket_acl.grants:
        if "URI" in grant['Grantee']:
            log.info("Found Grant: "+str(grant))
            uri_list += grant['Grantee']["URI"]
            if "LogDelivery" in str(grant):
                preserve_log_delivery.append(grant)
    if preserve_log_delivery == "[]":
        preserve_log_delivery = False

    if "AllUsers" in uri_list or "AuthenticatedUsers" in uri_list:
        log.info("Violation found.  Grant ACL greater than Private")
        log.info("Attempting Automatic Resolution")
        try:
            # ACL was greater than Private, but contained LogDelivery.  Retaining only LogDelivery
            if preserve_log_delivery:
                s3_violations.append("ACL was greater than Private, but contained LogDelivery.  Resetting ACL to LogDelivery")
                owner = bucket_acl.owner
                print("Preserve was: " + str(preserve_log_delivery))
                acl_string = {}
                acl_string['Grants'] = []
                for grant in preserve_log_delivery:
                    acl_string['Grants'].append(grant)
                acl_string['Owner'] = owner
                log.info("Preserving")
                # Correct the ACL
                response = bucket_acl.put(AccessControlPolicy=acl_string)
                print(response)
                if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                     log.info(response)
                     s3_violations.append("--AUTOMATIC INTERVENTION SUCCESSFUL--")
                     s3_violations.append("Bucket ACL has been reverted to only contain LogDelivery automatically")
                else:
                    s3_violations.append("--AUTOMATIC INTERVENTION FAILED--")
                    s3_violations.append('PutBucketACL replied with something other than "200 OK". Manual followup recommended')
            else:
                s3_violations.append("ACL was greater than Private, and does not contain LogDelivery.  Resetting ACL to Private")
                # Correct the ACL
                response = bucket_acl.put(ACL='private')
                if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                    log.info(response)
                    s3_violations.append("--AUTOMATIC INTERVENTION SUCCESSFUL--")
                    s3_violations.append("Bucket ACL has been changed to Private automatically")
                else:
                    s3_violations.append("--AUTOMATIC INTERVENTION FAILED--")
                    s3_violations.append('PutBucketACL replied with something other than "200". Manual followup recommended')
            log.info(str(s3_violations))
            return False, s3_violations

        except Exception as err:
            s3_violations.append('Unable resolve violation automatically.  Error was: ' + str(err) + ' Manual followup recommended')
            log.info(s3_violations)
            # Since we can't resolve this event, 
            # we return false to notify stakeholders to intervene
            return False, s3_violations

    else:
       log.info("ACL is not in violation")
       return True, s3_violations

def invoke_alert(event, context, s3_violations):
    """Invoke Alerts and Actions."""
    log.info('Invoking Alert')
    subject, message = create_non_compliance_message(event, s3_violations)
    send_violation(event, context, subject, message)

def create_non_compliance_message(event, s3_violations):
    """Create Non Compliance Message."""
    log.info("Generating Non Compliance Message")
    subject = "Violation - Non-Private Bucket ACL found"
    message = s3_violations
    return subject, message


def send_violation(event, context, subject, message):
    """Send Violation Message."""
    outbound_topic_arn = os.environ["outbound_topic_arn"]
    findsnsregion = outbound_topic_arn.split(":")
    snsregion = findsnsregion[3]
    sendclient = boto3.client('sns', region_name=snsregion)
    try:
        body = ""
        body += "Security event encountered when entity:\n"
        body += json.dumps(event["detail"]["userIdentity"], indent=4)
        body += "\nIssued API call:\n\t"+event["detail"]["eventName"]+"\n\n"
        body += "Full ACL Request Details:\n"
        body += "===========================\n"
        body += json.dumps(event["detail"]["requestParameters"], indent=4)+"\n\n"
        body += "Timestamp: "+event['detail']['eventTime']+"\n"
        body += "Target Account: "+event['detail']['userIdentity']["accountId"]+"\n"
        body += "\n\nControl responded:\n"
        for line in message:
            body += "\t"+line+"\n"
        body += "\n\n"
        body += ("This notification was generated by the Lambda function "
                    + context.invoked_function_arn)
    except KeyError:
        # Since we can't provide all details
        # append a generic message instead
        body += "Additional Details available in the runtime log"

    try:
        sendclient.publish(
            TopicArn=outbound_topic_arn,
            Message=body,
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
