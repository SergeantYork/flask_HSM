import base64
import json
import logging
import sys
import requests
import hashlib
import os

# PATH = os.path.dirname(sys.executable) # for .exe only
PATH = os.path.dirname(os.path.realpath(__file__))  # for development only

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

    if response.status_code == 401:
        logging.error("Wrong API key - please check your API key")

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
            "hash": "{}".format(hash_value)
        }
    })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(token)
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    print('OAEP response {}'.format(response))
    if response.status_code == 404:
        logging.error("Wrong key or hash value unable to sign")
    response_json = response.json()["request_id"]
    response_print = json.dumps(response_json)
    logging.info("gen_auth_request_for_sign_OAEP: {}".format(response_print))
    return response_json


def gen_auth_request_for_sign_pss(token, api_endpoint, key, hash_value, alg):
    url = "{}/sys/v1/approval_requests".format(api_endpoint)
    payload = json.dumps({
        "method": "POST",
        "operation": "/crypto/v1/sign",
        "body": {
            "key": {
                "name": "{}".format(key)
            },
            "hash_alg": "{}".format(alg),
            "hash": "{}".format(hash_value),
            "mode": {
                "PSS": {
                    "mgf": {
                        "mgf1": {
                            "hash": "{}".format(alg)
                        }
                    }
                }
            }
        }
    })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(token)
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code == 404:
        logging.error("Wrong key or hash value unable to sign")
    response_json = response.json()["request_id"]
    response_print = json.dumps(response_json)
    logging.info("gen_auth_request_for_sign_PSS: {}".format(response_print))
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
    return response_json


def get_sign(api_endpoint, token, request_id):
    url = "{}/sys/v1/approval_requests/{}/result".format(api_endpoint, request_id)

    payload = {}
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(token)
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code == 401:
        logging.info("Signing Error")
    response_json = response.json()
    response_print = json.dumps(response_json)

    logging.info("get_sign: {}".format(response_print))
    return response_json


def rsa_verification(api_endpoint, token, key, alg, hash_value, user_signature):
    url = "{}/crypto/v1/verify".format(api_endpoint)
    payload = json.dumps({
        "key": {
            "name": "{}".format(key)
        },
        "hash_alg": "{}".format(alg),
        "hash": "{}".format(hash_value),
        "signature": "{}".format(user_signature)
    })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(token)
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code == 404:
        logging.error("Wrong key or hash value unable to sign")
    response_json = response.json()
    response_print = json.dumps(response_json)
    logging.info('OAEP_verification response_print: {}'.format(response_print))
    return response_json['result']


def pss_verification(api_endpoint, token, key, alg, hash_value, user_signature):
    url = "{}/crypto/v1/verify".format(api_endpoint)
    payload = json.dumps({
        "key": {
            "name": "{}".format(key)
        },
        "hash_alg": "{}".format(alg),
        "hash": "{}".format(hash_value),
        "signature": "{}".format(user_signature),
        "mode": {
            "PSS": {
                "mgf": {
                    "mgf1": {
                        "hash": "{}".format(alg)
                    }
                }
            }
        }
    })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(token)
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    if response.status_code == 404:
        logging.error("Wrong key or hash value unable to sign")
    response_json = response.json()
    response_print = json.dumps(response_json)
    logging.info('PSS_verification response_print: {}'.format(response_print))
    return response_json['result']


def hash_file(filename, operation):
    """"This function returns the SHA-256 hash
   of the file passed into it"""
    logging.info("hash_file address: {}".format(filename))
    # make a hash object

    # open file for reading in binary mode
    with open(filename, 'rb') as m:
        message = m.read()
        if operation == 'SHA2-224':
            h = hashlib.sha224(message)

        if operation == 'SHA2-256':
            h = hashlib.sha256(message)

        if operation == 'SHA2-384':
            h = hashlib.sha384(message)

        if operation == 'SHA2-512':
            h = hashlib.sha512(message)

    m.close()

    # return the hex representation of digest
    logging.info("*************the digest value : {}".format(h.digest()))
    digest = h.digest()
    logging.info("*************the length of digest : {}".format(len(digest)))
    return h.digest()
