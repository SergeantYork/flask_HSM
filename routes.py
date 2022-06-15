import os
import shutil
import sys
import logging
import time

from flask import (
    render_template,
    Flask, request, flash, url_for, session, send_file)
from werkzeug.utils import redirect, secure_filename

from models import SigningField

from my_HSM_Signing import call_streaming_signing

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ec9439cfc6c796ae2029594d'
app.config["UPLOAD_FOLDER"] = "static/"
end_point = "https://eu.smartkey.io/"
default_value = '0'
PATH = os.path.dirname(os.path.realpath(__file__))


sys.stdout = sys.stderr = open('static/flask_server.log', 'wt')
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


@app.route('/thank-you')
def signing_progress():
    digest = True
    api_key = session.get('api_key', None)
    signing_key = session.get('signing_key', None)
    file_name = session.get('file_name', None)
    path = PATH + '/static/{}'.format(file_name)
    signing_algorithm = session.get('signing_algorithm', None)
    file_type = session.get('digest', None)

    # flash("{}".format(api_key), default_value)
    # flash("{}".format(signing_key), default_value)
    # flash("{}".format(path), default_value)
    # flash("{}".format(signing_algorithm), default_value)
    # flash("{}".format(file_type), default_value)
    if file_type == 'image':
        digest = False
    # flash("{}".format(digest), default_value)
    call_streaming_signing(end_point, api_key, in_data=path, out_data='file_signed.txt', key_name=signing_key,
                           operation=signing_algorithm, digest=digest)

    return render_template('signing-progress.html')


# Simple form handling using raw HTML forms
@app.route('/signing-file', methods=['GET', 'POST'])
def signing_file():
    form = SigningField()

    if form.is_submitted():
        f = request.files['file']

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
    path = session.get('path', None)
    file_name = session.get('file_name', None)
    file_ending = "txt"
    download_path = ("{}_signature.{}".format(path, file_ending))
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_name))
    return send_file(download_path, as_attachment=True)


@app.route('/download_log')
def download_log_file():
    old_name = PATH + '/static/flask_server.log'
    file_name = session.get('path', None)
    time_stamp = time.time()
    new_name = PATH + '/{}_{}_log.txt'.format(file_name, time_stamp)
    # flash("{}".format(new_name), default_value)
    shutil.copy(old_name, new_name)
    download_path = new_name
    return send_file(download_path, as_attachment=True)


# Run the application
if __name__ == '__main__':
    app.run(debug=True)
