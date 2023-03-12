from uuid import UUID, uuid4
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as djangoValidationError

from ..validators import validate_phoneNumber


LOGIN_TYPE = {
    'username':'username', 
    'email':'email', 
    'phoneNumber':'phoneNumber'
}

def find_logintype(login_name):
    """
    function to quickly get login_type whether it is username, email, or phoneNumber.
    """
    if '@' in login_name:
        return LOGIN_TYPE['email']

    try:
        validate_phoneNumber(login_name)
        return LOGIN_TYPE['phoneNumber']
    except djangoValidationError:
        pass
    
    return LOGIN_TYPE['username']


def generate_unique_username():
    """
    function to generate unique username.
    """
    create_random_username = lambda: uuid4().hex         # lambda function to generate timestamp-based username
    unique = False

    while not unique:
        try:
            username = create_random_username()
            get_user_model().objects.get(username=username)
        except get_user_model().DoesNotExist:
            unique=True
    return username


def validate_uuid4(uuid_string):
    """
    bool function to check for system generated username.
    """
    uuid_string = uuid_string.replace('-', '')

    try:
        val = UUID(uuid_string, version=4)
        return val.hex == uuid_string
    except ValueError:                                    # If it's a value error, then the string is not a valid hex code for a UUID.
        return False


def get_identityObj(identity):
    """
    Returns UserEmail or UserMobile object.

    parameter:
        identity : can be username/email/phoneNumber.
    """
    from ..models import UserEmail, UserMobile

    login_type = find_logintype(identity)
    identity_obj = None

    if login_type == LOGIN_TYPE['username']:
        user = get_user_model().objects.get(username=identity)
        identity_obj = user.get_primary_identity()

    elif login_type == LOGIN_TYPE['email']:
        identity_obj = UserEmail.objects.get(email=identity)

    elif login_type == LOGIN_TYPE['phoneNumber']:
        identity_obj = UserMobile.objects.get(phoneNumber=identity)
    return identity_obj
