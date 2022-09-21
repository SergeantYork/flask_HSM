import os
import shutil
import time
import sys
import logging
import termcolor
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA

from csv import DictReader
from typing import List, Dict

from flask import (
    render_template,
    Flask, request, session, send_file)
from werkzeug.utils import secure_filename

from models import (SigningField, HmacField, HmacCsvField, Login, Verify)

from my_HSM_Signing import (append_new_line, get_auth, gen_auth_request_for_sign,
                            check_request_status, get_sign, hash_file, pss_verification, rsa_verification,
                            gen_auth_request_for_sign_pss)

from my_hmac_code import (gen_auth_request_for_hmac, get_hmac)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ec9439cfc6c796ae2029594d'
app.config["UPLOAD_FOLDER"] = "static/"
end_point = "https://eu.smartkey.io/"
default_value = '0'

# PATH = os.path.dirname(sys.executable)  # for .exe only

PATH = os.path.dirname(os.path.realpath(__file__))  # for development only

# sys.stdout = sys.stderr = open('static/flask_server.log', 'wt')

logging.basicConfig(filename='static/flask_server.log', level=logging.INFO, format="%(asctime)s - %(levelname)s - %("
                                                                                   "message)s")
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler = logging.FileHandler(filename='static/flask_server.log')
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)


# @app.route('/', methods=['GET', 'POST'])
# def login():
#     form = Login()
#     if form.is_submitted():
#         session['user_name'] = form.user_name.data
#         session['password'] = form.password.data
#         user_name = session.get('user_name', None)
#         password = session.get('password', None)
#         logging.info("user name: {}".format(user_name))
#         logging.info("password: {}".format(password))
#         return render_template('index.html')
#     return render_template('login.html', form=form)


@app.route('/')
def home_page():
    return render_template('index.html')


def sign_rsa(api_end_point, api_key, key, hash_value, alg, path):
    logging.info("sign_rsa api_end_point: {}".format(api_end_point))
    logging.info("sign_rsa api_key: {}".format(api_key))
    logging.info("sign_rsa key: {}".format(key))
    logging.info("sign_rsa hash_value: {}".format(hash_value))
    logging.info("sign_rsa alg: {}".format(alg))
    logging.info("sign_rsa path: {}".format(path))

    session['token'] = get_auth(api_end_point, api_key)
    token = session.get('token', None)

    logging.info("sign_rsa token: {}".format(token))

    session['request_id'] = gen_auth_request_for_sign(token, api_end_point, key, hash_value, alg)
    request_id = session.get('request_id', None)

    logging.info("sign_rsa request_id: {}".format(request_id))

    logging.info("my digest:{}".format(hash_value))

    match = {'status': 'PENDING'}

    logging.info('waiting for quorum approval')

    while match['status'] == 'PENDING':
        status = check_request_status(token, api_end_point)
        match = next(d for d in status if d['request_id'] == request_id)
        time.sleep(0.25)
        session['status'] = match['status']

    logging.info('Request approved getting signature')
    signature_string = get_sign(api_end_point, token, request_id)

    file_ending = "txt"

    with open('{}_signature.{}'.format(path, file_ending), 'w') as f:
        f.write('Request response:')

    logging.info('{}_signature.{}'.format(path, file_ending))
    append_new_line('{}_signature.{}'.format(path, file_ending),
                    "signature type RSA \n{}\n hash_value: {}".format(signature_string, hash_value))
    termcolor.cprint('The process finished your signature is ready please download from web page', 'green')

    logging.info('Request approved')

    if not match['status'] == 'PENDING':
        return 1


def sign_rsa_pss(api_end_point, api_key, key, hash_value, alg, path):
    logging.info("sign_rsa api_end_point: {}".format(api_end_point))
    logging.info("sign_rsa api_key: {}".format(api_key))
    logging.info("sign_rsa key: {}".format(key))
    logging.info("sign_rsa hash_value: {}".format(hash_value))
    logging.info("sign_rsa alg: {}".format(alg))
    logging.info("sign_rsa path: {}".format(path))

    session['token'] = get_auth(api_end_point, api_key)
    token = session.get('token', None)

    logging.info("sign_rsa token: {}".format(token))

    session['request_id'] = gen_auth_request_for_sign_pss(token, api_end_point, key, hash_value, alg)
    request_id = session.get('request_id', None)

    logging.info("sign_rsa request_id: {}".format(request_id))

    logging.info("my digest:{}".format(hash_value))

    match = {'status': 'PENDING'}

    logging.info('waiting for quorum approval')
    while match['status'] == 'PENDING':
        status = check_request_status(token, api_end_point)
        match = next(d for d in status if d['request_id'] == request_id)
        time.sleep(0.25)
        session['status'] = match['status']

    logging.info('Request approved getting signature')
    signature_string = get_sign(api_end_point, token, request_id)

    file_ending = "txt"

    with open('{}_signature.{}'.format(path, file_ending), 'w') as f:
        f.write('Request response:')
    logging.info('{}_signature.{}'.format(path, file_ending))
    append_new_line('{}_signature.{}'.format(path, file_ending),
                    "signature type RSA_PSS \n {}\n hash_value: {}".format(signature_string, hash_value))
    termcolor.cprint('The process finished your signature is ready please download from web page', 'green')

    logging.info('Request approved')

    if not match['status'] == 'PENDING':
        return 1


@app.route('/signing-progress')
def signing_progress():
    api_key = session.get('api_key', None)
    signing_key = session.get('signing_key', None)
    file_name = session.get('file_name', None)
    path = PATH + '/static/{}'.format(file_name)
    session['full_path'] = PATH + '/static/'
    signing_algorithm = session.get('signing_algorithm', None)
    file_type = session.get('file_type', None)
    signing_type = session.get('signing_type', None)
    file_signed = -1
    logging.info("file path: {}".format(path))

    if file_type == 'image':
        result = hash_file(path, signing_algorithm)
        result_digest = bytearray(result)
        logging.info("SHA-Digest Generation")

    if file_type == 'Digest':
        fh = open("{}".format(path), 'rb')
        result_digest = bytearray(fh.read)

    logging.info("the digest value : {}".format(result_digest))
    hash_value = base64.b64encode(result_digest).decode("utf-8")
    logging.info("the hash value : {}".format(hash_value))
    api_key = api_key
    api_end_point = end_point
    key = signing_key

    if signing_algorithm == 'SHA2-224':
        alg = 'Sha224'
    if signing_algorithm == 'SHA2-256':
        alg = 'Sha256'
    if signing_algorithm == 'SHA2-384':
        alg = 'Sha384'
    if signing_algorithm == 'SHA2-512':
        alg = 'Sha512'

    if signing_type == 'RSA-PKCSV1.5':
        file_signed = sign_rsa(api_end_point, api_key, key, hash_value, alg, path)

    if signing_type == 'RSA-PSS':
        file_signed = sign_rsa_pss(api_end_point, api_key, key, hash_value, alg, path)

    if file_signed == 1:
        return render_template('download-page.html')
    return render_template('signing-progress.html')


@app.route('/hmac-progress')
def hmac_progress():
    csv = session.get('csv', None)

    if not csv:
        api_key = session.get('api_key', None)
        key = session.get('hmac_key', None)
        serial_num = session.get('serial_num', None)
        path = PATH + '/static/'
        session['full_path'] = path
        hmac_algorithm = session.get('signing_algorithm', None)

        logging.info("file path: {}".format(path))

        if hmac_algorithm == 'SHA2-224':
            alg = 'Sha224'
        if hmac_algorithm == 'SHA2-256':
            alg = 'Sha256'
        if hmac_algorithm == 'SHA2-384':
            alg = 'Sha384'
        if hmac_algorithm == 'SHA2-512':
            alg = 'Sha512'

        token = get_auth(api_key=api_key, api_endpoint=end_point)

        print('api key: {}\n token: {}\n key name: {}\n algorithm: {}\n serial number: {}\n'.format(api_key, token, key,
                                                                                                    alg,
                                                                                                    serial_num))
        logging.info('api key: {}\n token: {}\n key name: {}\n algorithm: {}\n serial number: {}\n'.format(api_key,
                                                                                                           token,
                                                                                                           key, alg,
                                                                                                           serial_num))
        request_id = gen_auth_request_for_hmac(token=token, key=key, alg=alg, serial_num=serial_num)

        match = {'status': 'PENDING'}

        while match['status'] == 'PENDING':
            status = check_request_status(token=token, api_endpoint=end_point)

            match = next(d for d in status if d['request_id'] == request_id)

            print('Quorum {}\n'.format(match['status']))

            logging.info('Quorum {}\n'.format(match['status']))

            time.sleep(0.25)

        if match['status'] == 'APPROVED':
            print('request approved getting the HMAC\n')

            logging.info('request approved getting the HMAC\n')

            hmac_response = get_hmac(token, request_id)
            hmac_raw = hmac_response['body']['mac']
            hmac_code = hmac_raw[:32].upper()

            logging.info('Here is your HMAC raw: {}\n'.format(hmac_response['body']['mac']))
            print('Here is your HMAC truncated : {}\n'.format(hmac_code))

            file_ending = "txt"
            hmac_file = '{}_hmac_code.{}'.format(serial_num, file_ending)

            with open('{}{}_hmac_code.{}'.format(path, serial_num, file_ending), 'w') as f:
                f.write('Request response:\n hmac raw: {}\n hmac code: {}\n'.format(hmac_raw, hmac_code))

            logging.info('file name: {}_hmac_code.{}'.format(serial_num, file_ending))

            session['hmac_full_path'] = path + hmac_file
            session['file_name'] = hmac_file

            termcolor.cprint('The process finished your password is ready please download from web page', 'green')

            logging.info('Request approved')

        if not match['status'] == 'PENDING':
            return render_template('hmac-download-page.html')

        return render_template('signing-progress.html')

    if csv:
        api_key = session.get('api_key', None)
        key = session.get('hmac_key', None)
        file_name = session.get('file_name', None)
        session['full_path'] = PATH + '/static/'
        path = PATH + '/static/{}'.format(file_name)
        hmac_algorithm = session.get('signing_algorithm', None)

        logging.info("file path: {}".format(path))
        if hmac_algorithm == 'SHA2-224':
            alg = 'Sha224'
        if hmac_algorithm == 'SHA2-256':
            alg = 'Sha256'
        if hmac_algorithm == 'SHA2-384':
            alg = 'Sha384'
        if hmac_algorithm == 'SHA2-512':
            alg = 'Sha512'

        token = get_auth(api_key=api_key, api_endpoint=end_point)

        print('api key: {}\n token: {}\n key name: {}\n algorithm: {}\n '.format(api_key, token, key, alg))
        logging.info('api key: {}\n token: {}\n key name: {}\n algorithm: {}\n'.format(api_key, token, key, alg))

        filename_handler = open('{}'.format(path), 'r', encoding="utf8")
        csv_reader = DictReader(filename_handler)
        table: List[Dict[str, str]] = []
        for row in csv_reader:
            int_row: Dict[str, str] = {}
            for column in row:
                int_row[column] = str(row[column])
            table.append(int_row)
        filename_handler.close()

        for row in table:

            serial_num = row['serial num']

            request_id = gen_auth_request_for_hmac(token=token, key=key, alg=alg, serial_num=serial_num)

            match = {'status': 'PENDING'}

            while match['status'] == 'PENDING':
                status = check_request_status(token=token, api_endpoint=end_point)

                match = next(d for d in status if d['request_id'] == request_id)

                print('Quorum {}\n'.format(match['status']))

                logging.info('Quorum {}\n'.format(match['status']))

                time.sleep(0.25)

            if match['status'] == 'APPROVED':
                print('request approved getting the HMAC\n')

                logging.info('request approved getting the HMAC\n')

                hmac_response = get_hmac(token, request_id)

                hmac_raw = hmac_response['body']['mac']

                hmac_code = hmac_raw[:32].upper()

                row['hmac_pass'] = hmac_code

        print('the new table: {}'.format(table))
        session['hmac_table'] = table

    if not match['status'] == 'PENDING':
        return render_template('hmac-download-page.html')

    return render_template('signing-progress.html')


@app.route('/hmac-code', methods=['GET', 'POST'])
def hmac_code():
    form = HmacField()

    if form.is_submitted():
        session['csv'] = False

        session['api_key'] = form.api_key.data

        session['hmac_key'] = form.key_name.data

        session['serial_num'] = form.serial_num.data

        session['path'] = app.config['UPLOAD_FOLDER']

        session['signing_algorithm'] = form.signing_alg.data

        return render_template('hmac-progress.html')

    return render_template('hmac-code.html', form=form)


@app.route('/hmac-choose', methods=['GET', 'POST'])
def hmac_choose():
    return render_template('hmac-choose.html')


@app.route('/signing-file', methods=['GET', 'POST'])
def signing_file():
    form = SigningField()

    if form.is_submitted():
        f = request.files['media']

        file_name = secure_filename(f.filename)

        f.save(app.config['UPLOAD_FOLDER'] + file_name)

        session['api_key'] = form.api_key.data

        session['signing_key'] = form.key_name.data

        session['file_name'] = file_name

        session['path'] = app.config['UPLOAD_FOLDER'] + file_name

        session['signing_algorithm'] = form.signing_alg.data

        session['file_type'] = form.file_type.data

        session['signing_type'] = form.signing_type.data

        return render_template('signing-progress.html')

    return render_template('signing-file.html', form=form)


@app.route('/verify-sign', methods=['GET', 'POST'])
def verify_sign():
    form = Verify()

    if form.is_submitted():
        session['api_key'] = form.api_key.data

        session['signing_key'] = form.public_key.data

        session['user_digest'] = form.digest.data

        session['user_signature'] = form.signature.data

        session['signing_algorithm'] = form.signing_alg.data

        session['signing_type'] = form.signing_type.data

        return render_template('verify-progress.html')

    return render_template('verify-sign.html', form=form)


@app.route('/verify-progress')
def verify_progress():
    api_key = session.get('api_key', None)
    signing_key = session.get('signing_key', None)
    user_signature = session.get('user_signature', None)
    user_digest = session.get('user_digest', None)
    signing_algorithm = session.get('signing_algorithm', None)
    signing_type = session.get('signing_type', None)
    logging.info("the digest value : {}".format(user_digest))
    logging.info('the user digest length :{}'.format(len(user_digest)))
    # api_end_point = end_point

    if signing_algorithm == 'SHA2-224':
        alg = 'Sha224'
    if signing_algorithm == 'SHA2-256':
        alg = 'Sha256'
    if signing_algorithm == 'SHA2-384':
        alg = 'Sha384'
    if signing_algorithm == 'SHA2-512':
        alg = 'Sha512'

    # this part is for hard coded verification using DSM
    # api_key = ''
    # session['token'] = get_auth(api_end_point, api_key)
    # token = session.get('token', None)

    # if signing_type == 'RSA-PSS':
    #     key = 'RSA'
    #     session['verification_result'] = pss_verification(token=token, api_endpoint=api_end_point, key=key,
    #                                                       hash_value=user_digest,
    #                                                       alg=alg, user_signature=user_signature)
    #     verification_res = session.get('verification_result', None)
    #     logging.info('RSA-PSS verification result: {}'.format(verification_res))
    #     print('RSA-PSS verification result: {}'.format(verification_res))
    #
    # if signing_type == 'RSA-PKCSV1.5':
    #     key = 'RSA'
    #     session['verification_result'] = rsa_verification(token=token, api_endpoint=api_end_point, key=key,
    #                                                       hash_value=user_digest,
    #                                                       alg=alg, user_signature=user_signature)
    #     verification_res = session.get('verification_result', None)
    #     logging.info('RSA-PKCSV1.5 verification result: {}'.format(verification_res))
    #     print('RSA-PKCSV1.5 verification result: {}'.format(verification_res))

    pem_prefix = '-----BEGIN RSA PUBLIC KEY-----\n'
    pem_suffix = '\n-----END RSA PUBLIC KEY-----'
    public_key = signing_key
    pem_key = '{}{}{}'.format(pem_prefix, public_key, pem_suffix)
    logging.info('{}'.format(pem_key))

    with open('rsa.pub', 'w') as f:
        f.write('{}'.format(pem_key))

    public_key_direct_import = serialization.load_pem_public_key(open('rsa.pub', 'rb').read())
    public_key_direct_import_pem = public_key_direct_import.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    logging.info('The public key direct import: {}'.format(public_key_direct_import_pem.splitlines()))

    user_digest_base64_bytes = user_digest.encode('ascii')
    user_digest_bytes = base64.b64decode(user_digest_base64_bytes)
    user_signature_base64_bytes = user_signature.encode('ascii')
    user_signature_bytes = base64.b64decode(user_signature_base64_bytes)

    logging.info('*****The user_digest length: {}\n and value {}'.format(len(user_digest_bytes), user_digest_bytes))
    logging.info('*****The user_signature length: {}\n and value {}'.format(len(user_signature_bytes),
                                                                            user_signature_bytes))

    if signing_type == 'RSA-PKCSV1.5':
        if signing_algorithm == 'SHA2-224':
            res = public_key_direct_import.verify(user_signature_bytes, user_digest_bytes, padding.PKCS1v15(),
                                                  Prehashed(hashes.SHA224()))
            logging.info('python verification successful {}'.format(res))
        if signing_algorithm == 'SHA2-256':
            res = public_key_direct_import.verify(user_signature_bytes, user_digest_bytes, padding.PKCS1v15(),
                                                  Prehashed(hashes.SHA256()))
            logging.info('python verification successful {}'.format(res))
        if signing_algorithm == 'SHA2-384':
            res = public_key_direct_import.verify(user_signature_bytes, user_digest_bytes, padding.PKCS1v15(),
                                                  Prehashed(hashes.SHA384()))
            logging.info('python verification successful {}'.format(res))
        if signing_algorithm == 'SHA2-512':
            res = public_key_direct_import.verify(user_signature_bytes, user_digest_bytes, padding.PKCS1v15(),
                                                  Prehashed(hashes.SHA512()))
        logging.info('python verification successful {}'.format(res))

        if res is None:
            logging.info("verification was successful")
            return render_template('verification-result.html')
        else:
            logging.info("verification was not successful")
            return render_template('error_page.html')

    if signing_type == 'RSA-PSS':
        if signing_algorithm == 'SHA2-224':
            res = public_key_direct_import.verify(user_signature_bytes, user_digest_bytes, padding.PSS(
                mgf=padding.MGF1(hashes.SHA224()), salt_length=padding.PSS.AUTO), Prehashed(hashes.SHA224()))
            logging.info('python verification successful {}'.format(res))
        if signing_algorithm == 'SHA2-256':
            res = public_key_direct_import.verify(user_signature_bytes, user_digest_bytes, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO), Prehashed(hashes.SHA256()))
            logging.info('python verification successful {}'.format(res))
        if signing_algorithm == 'SHA2-384':
            res = public_key_direct_import.verify(user_signature_bytes, user_digest_bytes, padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.AUTO), Prehashed(hashes.SHA384()))
            logging.info('python verification successful {}'.format(res))
        if signing_algorithm == 'SHA2-512':
            res = public_key_direct_import.verify(user_signature_bytes, user_digest_bytes, padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.AUTO), Prehashed(hashes.SHA512()))
        logging.info('python verification successful {}'.format(res))

        if res is None:
            logging.info("verification was successful")
            return render_template('verification-result.html')
        else:
            logging.info("verification was not successful")
            return render_template('error_page.html')


@app.route('/hmac-csv', methods=['GET', 'POST'])
def hmac_code_csv():
    form = HmacCsvField()

    if form.is_submitted():
        f = request.files['media']

        file_name = secure_filename(f.filename)

        f.save(app.config['UPLOAD_FOLDER'] + file_name)

        session['csv'] = True

        session['file_name'] = file_name

        session['api_key'] = form.api_key.data

        session['hmac_key'] = form.key_name.data

        session['path'] = app.config['UPLOAD_FOLDER']

        session['signing_algorithm'] = form.signing_alg.data

        return render_template('hmac-progress.html')

    return render_template('hmac-csv.html', form=form)


@app.route('/download')
def download_signature():
    file_name = session.get('file_name', None)
    file_ending = "txt"
    full_path = session.get('full_path', None)
    logger.info('full path download: {}'.format(full_path))
    download_path = ("{}{}_signature.{}".format(full_path, file_name, file_ending))
    logger.info('full path download with file name: {}'.format(download_path))
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
    return send_file(download_path, as_attachment=True)


@app.route('/download-hmac')
def download_hmac():
    csv = session.get('csv', None)
    if not csv:
        download_path = session.get('hmac_full_path', None)
        logger.info('full path download with file name: {}'.format(download_path))
        return send_file(download_path, as_attachment=True)

    if csv:
        file_name = session.get('file_name', None)
        hmac_table = session.get('hmac_table', None)
        new_file_name = '{}_new.csv'.format(file_name)
        path = session.get('full_path', None)
        download_path = path + '{}'.format(new_file_name)
        print('new csv file download path: {}'.format(download_path))

        with open('{}'.format(download_path), 'w') as f:
            for row in hmac_table:
                for key in row.keys():
                    f.write("%s, %s\n" % (key, row[key]))

        return send_file(download_path, as_attachment=True)


@app.route('/download_log')
def download_log_file():
    path = session.get('full_path', None)
    old_name = path + '/flask_server.log'
    file_name = session.get('file_name', None)
    logger.info('new_name: {}'.format(old_name))
    time_stamp = time.time()
    new_name = path + '/{}_{}_log.txt'.format(file_name, time_stamp)
    logger.info('new_name: {}'.format(new_name))
    shutil.copy(old_name, new_name)
    download_path = new_name
    flask_server_file = open("{}".format(old_name), "w")
    flask_server_file.truncate()
    flask_server_file.close()
    logging.info('download_path: {}'.format(download_path))
    return send_file(download_path, as_attachment=True)


@app.errorhandler(500)
def not_found(e):
    return render_template('error_page.html'), 500


@app.errorhandler(404)
def not_found(e):
    return render_template('error_page.html'), 404


# Run the application
if __name__ == '__main__':
    app.run(debug=True)
