from django.core.exceptions import ValidationError as djangoValidationError
from django.core.validators import RegexValidator


def only_whitespace(value):
    """validates value to make sure it doesn't contain only blank spaces."""
    value = value.strip()
    if value == '':
        raise djangoValidationError("username cannot contain only whitespaces.")
        

def contains_atTheRate(username):
    """validates username to make sure it doesn't contain '@' symbol."""
    if '@' in username:
        raise djangoValidationError("username cannot contain special character @.")


def startswith_plus(username):
    """validates username to make sure it does not start with '+' symbol."""
    if username.startswith('+'):
        raise djangoValidationError("username cannot start with special character +.")


def only_numeric(username):
    """validates username is not fully numeric."""
    if username.isnumeric():
        raise djangoValidationError("username cannot be only numeric.")


def validate_username(username):
    """
    validate username as containing only_whitespace, contains_atTheRate, startswith_plus, only_numeric.
    """
    username_validators = [only_whitespace, contains_atTheRate, startswith_plus, only_numeric]
    errors = []

    for validator in username_validators:
        try:
            validator(username)
        except djangoValidationError as err:
            errors.append(err)
    
    if errors:
        raise djangoValidationError(errors)
        

regex = r"^(?:(?:\+|0{0,2})91(\s*|[\-])?|[0]?)?([6789]\d{2}([ -]?)\d{3}([ -]?)\d{4})$"
validate_phoneNumber = RegexValidator(regex, message="Enter only valid phone number.")

"""
Valid Entries:
    6856438922
    7856128945
    8945562713
    9998564723
    +91-9883443344
    09883443344
    919883443344
    0919883443344
    +919883443344
    +91-9883443344
    0091-9883443344
    +91 9883443344
    +91-785-612-8945
    +91 999 856 4723

Invalid Entries:
    WAQU9876567892
    ABCD9876541212
    0226-895623124
    0924645236
    0222-895612
    098-8956124
    022-2413184
"""
