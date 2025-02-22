import json
import http.client
import urllib.parse
import os
import logging
import base64
import basic_auth
from base64 import b64decode, b64encode
from hmac_validation import validate_hmac
from totp_validation import *
from flask import Response

# create logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):

    print('EVENT', event)
    global response
    token = None

    if 'authorization' in event['headers']:
        token = event['headers']['authorization']
        
        
    elif 'Authorization' in event['headers']:
        token = event['headers']['Authorization']
    # elif 'x-pki-hmac' in event['headers'] :
    #     hmac_value = event['headers']['x-pki-hmac'] 
    
    param_value= event.get('queryStringParameters',{})
    hmac_value = param_value.get('x-pki-hmac','')
    print("hmac:",hmac_value)
    
    body_value = event.get("body",{})
    json_value = json.loads(body_value)
    hmac_body =  json_value['message']

    print("body:",hmac_body)
    print("token: ",token)
    split = token.split(' ')
    token_auth_check = split[0]

    if token_auth_check == "Bearer":
        logger.info("IDAM OAUTH CALL")
        token = split[1]
        print('REQUEST TOKEN', token)

        introspection_endpoint = os.environ['idamEndpoint']
        introspection_path = os.environ['idamIntrospectionAPI']

        headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
        }

        data = urllib.parse.urlencode({
        'token': token
        })

        conn = http.client.HTTPSConnection(introspection_endpoint)
        conn.request('POST', introspection_path, data, headers=headers)
        response = conn.getresponse()
        response_body = response.read().decode()
        response_json = json.loads(response_body)
        response=response.status
        return idamoauth_policy_check(event,response_json,response)
    
      
    elif token_auth_check == "Basic":
        logger.info("TOTP CALL")
        totp_response=basic_auth_totp_check(token)
        response=totp_response.status_code
        return totp_policy_check(event,response)
    
    else:
        logger.info("HMAC CALL")
        hmac_response=validate_hmac(hmac_value,hmac_body)
        response=hmac_response.status_code
        # return hmac_policy_check(event,response)
        return response


def idamoauth_policy_check(event,response_json,response_code):

    if response_code == 200:
        if response_json.get('active'):
            logger.info("Token Validation - SUCCESS")
            return generate_policy('user', 'Allow', event['methodArn'])
        else:
            logger.info("Token Validation - FAILED")
            return generate_policy('user', 'Deny', event['methodArn'])
    else:
        return generate_policy('user', 'Deny', event['methodArn'])
    
def hmac_policy_check(event,response_code):

    if response_code == 200:
            logger.info("Token Validation - SUCCESS")
            return generate_policy('user', 'Allow', event['methodArn'])
    elif response_code == 401:
            logger.info("Token Validation - FAILED")
            return generate_policy('user', 'Deny', event['methodArn'])
    else:
        return generate_policy('user', 'Deny', event['methodArn'])
        
def totp_policy_check(event,response_code):

    if response_code == 200:
        logger.info("Token Validation - SUCCESS")
        return generate_policy('user', 'Allow', event['methodArn'])
    elif response_code == 401:
        logger.info("401: Token Validation - FAILED")
        return generate_policy('user', 'Deny', event['methodArn'])
    else:
        return generate_policy('user', 'Deny', event['methodArn'])        
        
def basic_auth_totp_check(token):

    print('REQUEST TOKEN', token)
    split = token.split(' ')
    token = split[1]

    # Extract username and password from Authorization header
    authInput = "========"
    basic_auth_token = token + authInput
    splitinput = basic_auth_token.strip().split(' ')
    username, password = b64decode(splitinput[0]).decode().split(':', 1)
    print('USERNAME:', username)
    print('PASSWORD:', password)
    is_totp_valid=validate_login(username, password)
    print('STATUS CODE', is_totp_valid.status_code)
    logger.info(is_totp_valid.status_code)
    return is_totp_valid
    

def generate_policy(principal_id, effect, resource):
    policy = {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': resource
                }
            ],
        }
    }
    return policy