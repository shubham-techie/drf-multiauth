
from django.utils import http, encoding
from django.contrib.auth import get_user_model, backends
from django.core.exceptions import ValidationError as djangoValidationError

from .models import UserIdentity, UserEmail, UserMobile
from .utils import LOGIN_TYPE, find_logintype
from .settings import api_settings
from .exceptions import NoPrimaryIdentity, IdentityModelObjectError, AuthenticationFailed as djangoAuthenticationFailed


# no need to use __iexact to ignore case for username, email, phoneNumber
# because all entered values are first passed through and values are converted and represented as of respective fields.

class UsernamePaswordBackend(backends.ModelBackend):
    """
    Backend to authenticate with username and password.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return
    
        if not find_logintype(username)==LOGIN_TYPE['username']:
            return

        try:
            user = get_user_model().objects.get(username=username)
        except get_user_model().DoesNotExist:
            print("username DoesNotExist")
            return
        else:
            if user.check_password(password):
                if self.user_can_authenticate(user):
                    return user
                else:
                    raise djangoAuthenticationFailed("Account is inactive!. Kindly contact admin.")
            else:
                raise djangoAuthenticationFailed("username-password mismatch.")



class EmailPasswordBackend(backends.ModelBackend):
    """
    Backend to authenticate with email and password.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return

        if not find_logintype(username)==LOGIN_TYPE['email']:
            return

        try:
            email = UserEmail.objects.get(email=username)
        except UserEmail.DoesNotExist:
            print("email DoesNotExist")
            return
        else:
            if email.user.check_password(password) :
                if self.user_can_authenticate(email.user) and email.is_verified:
                    return email.user
                else:
                    raise djangoAuthenticationFailed("Either account is inactive or email is not verified. Try verifying your email or contact admin.")
            else:
                raise djangoAuthenticationFailed(["email-password mismatch."])



class MobilePasswordBackend(backends.ModelBackend):
    """
    Backend to authenticate with phoneNumber and password.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return  

        if not find_logintype(username)==LOGIN_TYPE['phoneNumber']:
            return

        try:
            phoneNumber = UserMobile.objects.get(phoneNumber = username)
        except UserMobile.DoesNotExist:
            print("phoneNumber DoesNotExist")
            return
        else:
            if phoneNumber.user.check_password(password):
                if self.user_can_authenticate(phoneNumber.user) and phoneNumber.is_verified:
                    return phoneNumber.user
                else:
                    raise djangoAuthenticationFailed("Either account is inactive or phoneNumber is not verified. Try verifying your phoneNumber or contact admin.")
            else:
                raise djangoAuthenticationFailed("phoneNumber-password mismatch.")



class UsernameOtpBackend(backends.ModelBackend):
    """
    Backend to authenticate with username and otp.
    """
    def authenticate(self, request, username=None, otp=None, **kwargs):
        if username is None or otp is None:
            return

        if not find_logintype(username)==LOGIN_TYPE['username']:
            return

        try:
            user = get_user_model().objects.get(username=username)
            identity_obj = user.get_primary_identity()
        except get_user_model().DoesNotExist:
            print("username DoesNotExist")
            return
        except (NoPrimaryIdentity, IdentityModelObjectError) as err:        
            raise djangoAuthenticationFailed(err.args[0])
        else:
            validate_otp_class = api_settings.VALIDATE_OTP_CLASS
            try:
                validate_otp_class.validate_otp(username, otp, update_timestamp=False)
            except djangoValidationError as err:
                raise djangoAuthenticationFailed(err.args[0])
            else:
                if self.user_can_authenticate(user) and identity_obj.is_verified:
                    return user
                else:
                    raise djangoAuthenticationFailed("Either account is inactive or primary identity is not verified. Try verifying your primary identity or contact admin.")

     

class EmailOtpBackend(backends.ModelBackend):
    """
    Backend to authenticate with email and otp.
    """
    def authenticate(self, request, username=None, otp=None, **kwargs):
        if username is None or otp is None:
            return

        if not find_logintype(username)==LOGIN_TYPE['email']:
            return

        try:
            identity_obj = UserEmail.objects.get(email=username)
        except UserEmail.DoesNotExist:
            print("email DoesNotExist")
            return
        else:
            validate_otp_class = api_settings.VALIDATE_OTP_CLASS
            try:
                validate_otp_class.validate_otp(username, otp, update_timestamp=False)
            except djangoValidationError as err:
                raise djangoAuthenticationFailed(err.args[0])
            else:
                if self.user_can_authenticate(identity_obj.user) and identity_obj.is_verified:
                    return identity_obj.user
                else:
                    raise djangoAuthenticationFailed("Either account is inactive or email is not verified. Try verifying your email or contact admin.")



class MobileOtpBackend(backends.ModelBackend):
    """
    Backend to authenticate with phoneNumber and otp.
    """
    def authenticate(self, request, username=None, otp=None, **kwargs):
        if username is None or otp is None:
            return

        if not find_logintype(username)==LOGIN_TYPE['phoneNumber']:
            return

        try:
            identity_obj = UserMobile.objects.get(phoneNumber = username)
        except UserMobile.DoesNotExist:
            print("phoneNumber DoesNotExist")
            return
        else:
            validate_otp_class = api_settings.VALIDATE_OTP_CLASS
            try:
                validate_otp_class.validate_otp(username, otp, update_timestamp=False)
            except djangoValidationError as err:
                raise djangoAuthenticationFailed(err.args[0])
            else:
                if self.user_can_authenticate(identity_obj.user) and identity_obj.is_verified:
                    return identity_obj.user
                else:
                    raise djangoAuthenticationFailed("Either account is inactive or phoneNumber is not verified. Try verifying your phoneNumber or contact admin.")



class MagicLinkBackend(backends.ModelBackend):
    """
    Backend to authenticate with magic link.
    """
    def authenticate(self, request, username=None, token=None, **kwargs):
        if username is None or token is None:
            return

        uidb64, iidb64 = username.split("-")
        validate_magiclink_class = api_settings.VALIDATE_MAGICLINK_CLASS
        try:
            validate_magiclink_class.validate_magiclink(uidb64, iidb64, token, update_timestamp=False)
        except djangoValidationError as err:
            raise djangoAuthenticationFailed(err.args[0])
        else:
            identity_id = encoding.force_str(http.urlsafe_base64_decode(iidb64))
            identity_obj = UserIdentity.objects.filter(pk=identity_id).first()
            
            if self.user_can_authenticate(identity_obj.user) and identity_obj.is_verified:
                return identity_obj.user
            else:
                raise djangoAuthenticationFailed("Either account is inactive or identity is not verified. Try verifying your identity or contact admin.")
