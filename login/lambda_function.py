"""Login function."""

import os
import boto3
import json
import logging


LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

def handler(event, _):
    """ Main handler """

    LOGGER.debug("Starting the handler.")
    LOGGER.info(event)

    if not event_body or not event_body["password"] or not event_body["username"]:
        return {
            "statusCode": 400,
            "body": "Bad request"
        }

    password_parameter = get_ssm_parameter("/lambda/mijnfotos-login/password")

    try:
        if event_body["password"] == password_parameter and event_body["username"] == "jpthur":
            LOGGER.info(f'Successful login for {event_body["username"]}.'
            response_headers = get_response_headers()

            return {
                "statusCode": 200,
                "body": json.dumps(response_headers),
                "headers": response_headers
            }
        else:
            LOGGER.info(f'Invalid login for {event_body["username"]}.'

            return {
                "statusCode": 403,
                "body": "Authentication failed",
                "headers": {
                    # clear any existing cookies
                    'Set-Cookie': 'CloudFront-Policy=',
                    'SEt-Cookie': 'CloudFront-Signature=',
                    'SET-Cookie': 'CloudFront-Key-Pair-Id='
                }
            }
    except:
        return {
                "statusCode": 500,
                "body": "Server error"
            }


def get_ssm_parameter(ssm_path):
    """ Retreive SSM parameter."""

    ssm_client = boto3.client("ssm")
    ssm_response = ssm_client.get_parameter(Name=ssm_path, WithDecryption=True)

    return ssm_response["Parameter"]["Value"]


def get_response_headers():
    """ Get headers."""

    session_duration = os.getenv("SESSION_DURATION")

    lambda_client = boto3.client("lambda")

    lambda_response = lambda_client.invoke(
        FunctionName="mijnfotos-cookies-lambda-cf",
        InvocationType="RequestResponse",
        Payload=b'bytes'|file
    )

    if lambda_response["StatusCode"] == 200:
        return lambda_response["Payload"]
    raise
