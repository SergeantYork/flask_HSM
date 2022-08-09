"""Form object declaration."""
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, SelectField


class SigningField(FlaskForm):
    api_key = TextAreaField(label="Enter API key")
    key_name = StringField(label="Enter key name")
    path = StringField(label="Enter file path")
    file_type = SelectField('Select image or digest', choices=[('image', 'image'), ('Digest',
                                                                                    'Digest')])
    signing_alg = SelectField('Select signing algorithm', choices=[('SHA2-224', 'SHA2-224 bit'),
                                                                   ('SHA2-256', 'SHA2-256 bit'),
                                                                   ('SHA2-384', 'SHA2-384 bit'),
                                                                   ('SHA2-512', 'SHA2-512 bit')])


class HmacField(FlaskForm):
    api_key = TextAreaField(label="Enter API key")
    key_name = StringField(label="Enter key name")
    serial_num = StringField(label="Enter serial number")
    signing_alg = SelectField('Select signing algorithm', choices=[('SHA2-224', 'SHA2-224 bit'),
                                                                   ('SHA2-256', 'SHA2-256 bit'),
                                                                   ('SHA2-384', 'SHA2-384 bit'),
                                                                   ('SHA2-512', 'SHA2-512 bit')])


class HmacCsvField(FlaskForm):
    api_key = TextAreaField(label="Enter API key")
    key_name = StringField(label="Enter key name")
    signing_alg = SelectField('Select signing algorithm', choices=[('SHA2-224', 'SHA2-224 bit'),
                                                                   ('SHA2-256', 'SHA2-256 bit'),
                                                                   ('SHA2-384', 'SHA2-384 bit'),
                                                                   ('SHA2-512', 'SHA2-512 bit')])


class Login(FlaskForm):
    user_name = TextAreaField(label="Enter user name")
    password = StringField(label="Enter password")
