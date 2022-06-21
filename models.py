"""Form object declaration."""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, SelectField


class SigningField(FlaskForm):
    api_key = TextAreaField(label="Enter API key")
    key_name = StringField(label="Enter key name")
    path = StringField(label="Enter file path")
    digest = SelectField('Select image or digest', choices=[(False, 'image'), (True,
                                                                               'Digest')])
    signing_alg = SelectField('Select signing algorithm', choices=[('SHA2-224', 'SHA2-224 bit'),
                                                                   ('SHA2-256', 'SHA2-256 bit'),
                                                                   ('SHA2-384', 'SHA2-384 bit'),
                                                                   ('SHA2-512', 'SHA2-512 bit')])
    submit = SubmitField(label='Submit')
