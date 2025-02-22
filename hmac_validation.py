import hmac
import hashlib
import os
from venv import logger
from flask import Response
# Set environment variables for local testing
# def get_secret():
#     secret_name = os.getenv('SECRET_NAME')
#     return secret_name
def generate_hmac(body, secret_key):
    secret_key= get_secret()
    hmac_result = hmac.new(secret_key.encode(),body.encode(),hashlib.sha256).hexdigest()
    return hmac_result
def validate_hmac(hmac_value,hmac_body):
    generated_hmac= generate_hmac(hmac_body)
    if not generated_hmac:
        return Response(status=500)  # Internal Server Error if HMAC generation fails
    print("hmac:",hmac_value)
    print("generated_hmac: ",generated_hmac)
    
