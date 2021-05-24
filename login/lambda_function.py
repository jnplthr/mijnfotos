"""Login function."""

import json
import logging
import boto3


LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)


def handler(event, _):
    """ Main handler """

    LOGGER.debug("Starting the handler.")
    LOGGER.info(event)

    body = json.loads(event["body"])

    if not body or not body["password"] or not body["username"]:
        return {"statusCode": 400, "body": "Bad request"}

    password_parameter = get_ssm_parameter("/lambda/mijnfotos-login/password")

    try:
        if body["password"] == password_parameter and body["username"] == "jpthur":
            LOGGER.info(f'Successful login for {body["username"]}.')
            header_information = get_response_headers()
            LOGGER.info(header_information)

            return {
                "statusCode": 200,
                "body": "Authentication succeeded",
                "headers": json.loads(header_information["body"]),
            }

        LOGGER.info(f'Invalid login for {body["username"]}.')
        return {
            "statusCode": 403,
            "body": "Authentication failed",
            "headers": {
                # clear any existing cookies
                "Set-Cookie": "CloudFront-Policy=",
                "SEt-Cookie": "CloudFront-Signature=",
                "SET-Cookie": "CloudFront-Key-Pair-Id=",
            },
        }
    except Exception as exception:
        LOGGER.error(exception)
        return {"statusCode": 500, "body": "Server error"}


def get_ssm_parameter(ssm_path):
    """ Retreive SSM parameter."""

    ssm_client = boto3.client("ssm")
    ssm_response = ssm_client.get_parameter(Name=ssm_path, WithDecryption=True)

    return ssm_response["Parameter"]["Value"]


def get_response_headers():
    """ Get headers."""

    lambda_client = boto3.client("lambda")

    lambda_response = lambda_client.invoke(
        FunctionName="mijnfotos-cookies-lambda-cf",
        InvocationType="RequestResponse",
        Payload='{"name": "test"}',
    )

    if lambda_response["StatusCode"] == 200:
        return json.loads(lambda_response["Payload"].read())
    raise
