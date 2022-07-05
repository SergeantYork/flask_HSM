import json
import requests
import os

PATH = os.path.dirname(os.path.realpath(__file__))
api_endpoint = 'https://eu.smartkey.io/'


def gen_auth_request_for_hmac(token, key, alg, serial_num):
    url = "{}sys/v1/approval_requests".format(api_endpoint)
    payload = json.dumps({
        "method": "POST",
        "operation": "/crypto/v1/mac",
        "body": {
            "key": {
                "name": "{}".format(key)
            },
            "alg": "{}".format(alg),
            "data": "{}".format(serial_num)
        }
    })
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(token)
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    if response.status_code == 404:
        print('key error please check the key\n')

    response_json = response.json()["request_id"]
    response_print = json.dumps(response_json)
    print('Your request ID from the HSM cloud: {}\n'.format(response_print))
    return response_json


def get_hmac(token, request_id):
    url = "{}/sys/v1/approval_requests/{}/result".format(api_endpoint, request_id)

    payload = {}

    headers = {

        'Content-Type': 'application/json',

        'Authorization': 'Bearer {}'.format(token)

    }

    response = requests.request("POST", url, headers=headers, data=payload)
    response_json = response.json()
    return response_json




