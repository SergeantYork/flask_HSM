import os
import shutil
import time
import sys
import logging
import termcolor
import base64

from flask import (
    render_template,
    Flask, request, session, send_file)
from werkzeug.utils import secure_filename

from models import SigningField

from my_HSM_Signing import (append_new_line, get_auth, gen_auth_request_for_sign
                            , check_request_status, get_sign, hash_file)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ec9439cfc6c796ae2029594d'
app.config["UPLOAD_FOLDER"] = "static/"
end_point = "https://eu.smartkey.io/"
default_value = '0'

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


@app.route('/')
def home_page():
    return render_template('index.html')


@app.route('/signing-progress')
def signing_progress():
    api_key = session.get('api_key', None)
    signing_key = session.get('signing_key', None)
    file_name = session.get('file_name', None)
    path = PATH + '/static/{}'.format(file_name)
    session['full_path'] = PATH + '/static/'
    signing_algorithm = session.get('signing_algorithm', None)
    file_type = session.get('file_type', None)

    logging.info("file path: {}".format(path))

    if file_type == 'image':
        result = hash_file(path, signing_algorithm)
        result_digest = bytearray(result)
        print("SHA-Digest Generation")

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
        alg = 'sha224'
    if signing_algorithm == 'SHA2-256':
        alg = 'Sha256'
    if signing_algorithm == 'SHA2-384':
        alg = 'Sha384'
    if signing_algorithm == 'SHA2-512':
        alg = 'Sha512'

    session['token'] = get_auth(api_end_point, api_key)
    token = session.get('token', None)
    session['request_id'] = gen_auth_request_for_sign(token, api_end_point, key, hash_value, alg)
    request_id = session.get('request_id', None)

    print("my digest:{}".format(hash_value))

    match = {'status': 'PENDING'}

    logging.info('waiting for quorum approval')

    while match['status'] == 'PENDING':
        status = check_request_status(token, api_end_point)
        match = next(d for d in status if d['request_id'] == request_id)
        time.sleep(0.25)
        session['status'] = match['status']
    logging.info('Request approved getting signature')
    print('Request approved getting signature')

    signature_string = get_sign(api_end_point, token, request_id)

    file_ending = "txt"

    with open('{}_signature.{}'.format(path, file_ending), 'w') as f:
        f.write('Request response:')

    print('{}_signature.{}'.format(path, file_ending))
    append_new_line('{}_signature.{}'.format(path, file_ending),
                    "{}".format(signature_string))
    print("\n")
    termcolor.cprint('The process finished your signature is ready please download from web page', 'green')

    logging.info('Request approved')
    if not match['status'] == 'PENDING':
        return render_template('download-page.html')
    return render_template('signing-progress.html')


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

        return render_template('signing-progress.html')

    return render_template('signing-file.html', form=form)


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


@app.route('/download_log')
def download_log_file():
    path = session.get('full_path', None)
    old_name = path + '/flask_server.log'
    logger.info('new_name: {}'.format(old_name))
    file_name = session.get('file_name', None)
    time_stamp = time.time()
    new_name = path + '/{}_{}_log.txt'.format(file_name, time_stamp)
    logger.info('new_name: {}'.format(new_name))
    shutil.copy(old_name, new_name)
    download_path = new_name
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
