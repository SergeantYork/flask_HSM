import contextlib
import os
import pathlib
import shutil
import time
import sys
import logging

from flask import (
    render_template,
    Flask, request, url_for, session, send_file, flash)
from werkzeug.utils import redirect, secure_filename

from models import SigningField

from my_HSM_Signing import call_streaming_signing

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ec9439cfc6c796ae2029594d'
app.config["UPLOAD_FOLDER"] = "static/"
end_point = "https://eu.smartkey.io/"
default_value = '0'

# PATH = os.path.dirname(sys.executable) for .exe only

PATH = os.path.dirname(os.path.realpath(__file__))

# sys.stdout = sys.stderr = open('static/flask_server.log', 'wt')

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
    digest = True
    api_key = session.get('api_key', None)
    signing_key = session.get('signing_key', None)
    file_name = session.get('file_name', None)
    path = PATH + '/static/{}'.format(file_name)
    session['full_path'] = PATH + '/static/'
    signing_algorithm = session.get('signing_algorithm', None)
    file_type = session.get('digest', None)
    # flash("{}".format(path), default_value)

    # flash("{}".format(api_key), default_value)
    # flash("{}".format(signing_key), default_value)
    # flash("{}".format(path), default_value)
    # flash("{}".format(signing_algorithm), default_value)
    # flash("{}".format(file_type), default_value)
    if file_type == 'image':
        digest = False
    # flash("{}".format(digest), default_value)
    logging.info("file path: {}".format(path))
    logging.info('waiting for quorum approval')
    call_streaming_signing(end_point, api_key, in_data=path, out_data='file_signed.txt', key_name=signing_key,
                           operation=signing_algorithm, digest=digest)
    logging.info('Request approved')
    logging.info('status from the routes: {}'.format(session['status']))
    return render_template('signing-progress.html')


# Simple form handling using raw HTML forms
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

        session['digest'] = form.digest.data

        return redirect(url_for('signing_progress'))

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
    app.run(debug=False)
