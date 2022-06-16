import json
import logging

import requests
import time
import hashlib
import base64
import os

import termcolor
from termcolor import colored


PATH = os.path.dirname(os.path.realpath(__file__))

logging.basicConfig(filename='static/flask_server.log', level=logging.INFO, format="%(asctime)s - %(levelname)s - %("
                                                                                   "message)s")
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler = logging.FileHandler(filename='static/flask_server.log')
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)


def append_new_line(file_name, text_to_append):
    """Append given text as a new line at the end of file"""
    # Open the file in append & read mode ('a+')
    with open(file_name, "a+") as file_object:
        # Move read cursor to the start of file.
        file_object.seek(0)
        # If file is not empty then append '\n'
        data = file_object.read(100)
        if len(data) > 0:
            file_object.write("\n")
        # Append text at the end of file
        file_object.write(text_to_append)


def get_auth(api_endpoint, api_key):
    url = "{}/sys/v1/session/auth".format(api_endpoint)

    payload = {}
    headers = {'Authorization': 'Basic {}'.format(api_key)}

    response = requests.request("POST", url, headers=headers, data=payload)
    response_json = response.json()
    response_print = json.dumps(response_json)
    logging.info("get_auth: {}".format(response_print))
    return response_json["access_token"]


def gen_auth_request_for_sign(token, api_endpoint, key, hash_value, alg):
    url = "{}/sys/v1/approval_requests".format(api_endpoint)
    payload = json.dumps({
        "method": "POST",
        "operation": "/crypto/v1/sign",
        "body": {
            "key": {
                "name": "{}".format(key)
            },
            "hash_alg": "{}".format(alg),
            "data": "{}".format(hash_value)
        }
    })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(token)
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    response_json = response.json()["request_id"]
    response_print = json.dumps(response_json)
    logging.info("gen_auth_request_for_sign: {}".format(response_print))
    return response_json


def check_request_status(token, api_endpoint):
    url = "{}/sys/v1/approval_requests".format(api_endpoint)
    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(token)
    }
    response = requests.request("GET", url, headers=headers, data=payload)
    response_json = response.json()
    response_print = json.dumps(response_json)
    logging.info("check_request_status: {}".format(response_print))
    return response_json


def get_sign(api_endpoint, token, request_id):
    url = "{}/sys/v1/approval_requests/{}/result".format(api_endpoint, request_id)

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(token)
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    response_json = response.json()
    response_print = json.dumps(response_json)
    logging.info("get_sign: {}".format(response_print))
    return response_json


def hash_file(filename, operation):
    """"This function returns the SHA-256 hash
   of the file passed into it"""

    # make a hash object
    if operation == 'SHA2-256':
        h = hashlib.sha256()

    if operation == 'SHA3-256':
        h = hashlib.sha3_256()

    # open file for reading in binary mode
    with open(filename, 'rb') as file:
        # loop till the end of the file
        chunk = 0
        while chunk != b'':
            # read only 1024 bytes at a time
            chunk = file.read(1024)
            h.update(chunk)

    # return the hex representation of digest
    logging.info("the digest value : {}".format(h.digest()))
    print("the digest value : {}".format(h.digest()))
    return h.digest()


def signing_digest(api_endpoint, api_key, in_data, out_data, key_name, operation):
    fh = open("{}".format(in_data), 'rb')
    result_digest = bytearray(fh.read)
    hash_value = base64.b64encode(result_digest).decode("utf-8")
    logging.info("the hash value : {}".format(hash_value))
    print("the hash value : {}".format(hash_value))
    api_key = api_key
    api_endpoint = api_endpoint
    key = key_name

    if operation == 'SHA3-256':
        alg = 'Sha3256'
    if operation == 'SHA2-256':
        alg = 'Sha256'
    token = get_auth(api_endpoint, api_key)
    request_id = gen_auth_request_for_sign(token, api_endpoint, key, hash_value, alg)

    match = {'status': 'PENDING'}

    while match['status'] == 'PENDING':
        status = check_request_status(token, api_endpoint)
        match = next(d for d in status if d['request_id'] == request_id)
        time.sleep(0.25)
    logging.info('request approved getting signature')
    print('request approved getting signature')

    full_status_string = get_sign(api_endpoint, token, request_id)
    logging.info("get_sign full status respond {}".format(full_status_string))
    print("get_sign full status respond {}".format(full_status_string))
    file_name = str(in_data)
    file_ending = "txt"

    with open('{}_signature.{}'.format(in_data, file_ending), 'w') as f:
        f.write('Request response:')

    append_new_line('{}_signature.{}'.format(in_data, file_ending), "{}".format(full_status_string))


def signing(api_endpoint, api_key, in_data, out_data, key_name, operation):
    result = hash_file(in_data, operation)
    result_digest = bytearray(result)
    print("SHA3-Digest Generation")

    logging.info("the digest value : {}".format(result_digest))
    hash_value = base64.b64encode(result_digest).decode("utf-8")
    logging.info("the hash value : {}".format(hash_value))
    api_key = api_key
    api_endpoint = api_endpoint
    key = key_name

    if operation == 'SHA3-256':
        alg = 'Sha3256'
    if operation == 'SHA2-256':
        alg = 'Sha256'
    token = get_auth(api_endpoint, api_key)
    request_id = gen_auth_request_for_sign(token, api_endpoint, key, hash_value, alg)

    print("my digest:{}".format(hash_value))

    match = {'status': 'PENDING'}

    while match['status'] == 'PENDING':
        status = check_request_status(token, api_endpoint)
        match = next(d for d in status if d['request_id'] == request_id)
        time.sleep(0.25)
    logging.info('Request approved getting signature')
    print('Request approved getting signature')

    signature_string = get_sign(api_endpoint, token, request_id)

    file_ending = "txt"

    with open('{}_signature.{}'.format(in_data, file_ending), 'w') as f:
        f.write('Request response:')

    print('{}_signature.{}'.format(in_data, file_ending))
    append_new_line('{}_signature.{}'.format(in_data, file_ending),
                    "{}".format(signature_string))
    print("\n")
    termcolor.cprint('The process finished your signature is ready please download from web page', 'green')


def main(api_endpoint, api_key, in_data, out_data, key_name, operation, digest):

    if digest:
        signing_digest(api_endpoint, api_key, in_data, out_data, key_name, operation)
    else:
        signing(api_endpoint, api_key, in_data, out_data, key_name, operation)


def call_streaming_signing(api_endpoint, api_key, in_data, out_data, key_name, operation, digest):
    """call streaming method to pass the values from the GUI"""
    main(api_endpoint, api_key, in_data, out_data, key_name, operation, digest)
