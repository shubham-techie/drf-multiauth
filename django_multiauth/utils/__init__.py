from django.urls import reverse
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone, http, encoding
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail.message import EmailMultiAlternatives
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.exceptions import ValidationError as djangoValidationError

import pyotp
from threading import Thread
from datetime import datetime

from ..settings import api_settings
from .username_util import LOGIN_TYPE, find_logintype, generate_unique_username, validate_uuid4, get_identityObj


# ========================================================  Function ========================================================
def get_timestamp():
    timedelta = datetime.now() - datetime(2001,1,1)
    ts = int(timedelta.total_seconds())
    return ts

    
# ======================================================== Pyotp class ========================================================
class Pyotp:
    """
    class having staticmethods to generate and verify OTP.
    """

    @staticmethod
    def get_otp():
        """
        method to generate OTP.
        """
        secret = pyotp.random_base32()        
        totp = pyotp.TOTP(
            secret, 
            interval=settings.PASSWORD_RESET_TIMEOUT, 
            digits=api_settings.OTP_LENGTH
        )
        OTP = totp.now()
        key = {
            "secret":secret,
            "otp":OTP
        }
        return key


    @staticmethod
    def verify_otp(secret,otp):
        """
        Verifies OTP based on timestamp to confirm it is expired or not.
        """
        totp = pyotp.TOTP(
            secret, 
            interval=settings.PASSWORD_RESET_TIMEOUT, 
            digits=api_settings.OTP_LENGTH
        )
        verified = totp.verify(otp)
        return verified


# ======================================================== TokenGenerator class ========================================================
class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        login_timestamp = "" if (user.last_login is None) else (user.last_login.replace(microsecond=0, tzinfo=None))

        user_hash_value = f"{user.pk}{user.password}{login_timestamp}{timestamp}"
        identity_hash_value = ""

        identity_obj = user.useridentity.filter(verification_sent=True).first()
        if identity_obj:
            identity_hash_value = f"{identity_obj.pk}{identity_obj.verified_at}{identity_obj.verification_sent}{identity_obj.identity}"

        return user_hash_value + identity_hash_value
        
      
# ======================================================== Email class ========================================================
class EmailThread(Thread):
    def __init__(self, email):
        self.email = email
        Thread.__init__(self)

    def run(self):
        self.email.send()
        print("mail successfully send.")


class Email:
    @staticmethod
    def send_email(subject, to, template, **temp_kwargs):
        """
        sending email with Thread.
        """
        email = EmailMultiAlternatives(
            subject,
            None,
            settings.EMAIL_HOST_USER,
            [to]
        )
        body_template = render_to_string(template, temp_kwargs)
        email.attach_alternative(body_template, 'text/html')
        EmailThread(email).start()


# ======================================================== SMS class ========================================================
class SMS:
    """
    This class is to be overridden to send sms.
    """
    @staticmethod
    def send_sms(host, to, message):
        print("Temporary script to send otp on phonenumber.")
        print(message)


# ======================================================== OTP_dispatch class ========================================================
class OTP_dispatch:
    @staticmethod
    def send_otp(identity):
        """
        get OTP and send email/SMS.
        """
        # generating OTP.
        otp_class = api_settings.GENERATE_VERIFY_OTP_CLASS
        key = otp_class.get_otp()
        
        # getting objects.
        identity_obj = get_identityObj(identity)              # Here, identity_obj should be only email/phoneNumber
        user = identity_obj.user

        # saving otp and related values for further validation.
        user.otp = key['otp']
        user.secret = key['secret']
        user.save(update_fields=['otp','secret'])
        identity_obj.set_verification_sent()

        login_type = find_logintype(identity)

        # sending email
        if login_type == LOGIN_TYPE['email']:
            email_class = api_settings.SEND_EMAIL_CLASS
            email_class.send_email(
                subject = "Email Verification",
                to = identity_obj.email,
                template = 'email_verify.html',
                username = user.username,
                otp = key['otp'],
                otp_verification = True,
                expiry_time = settings.PASSWORD_RESET_TIMEOUT//60
            )

        # sending sms
        elif login_type == LOGIN_TYPE['phoneNumber']:
            sms_class = api_settings.SEND_SMS_CLASS
            sms_class.send_sms(
                host = "9112398322",
                to = identity_obj.phoneNumber,
                message = f"Hi {user.username}, \n Your OTP is {key['otp']}. \n Please do not share it with anyone."
            )


# ======================================================== MagicLink_dispatch class ========================================================  
class MagicLink_dispatch:
    @staticmethod
    def send_magiclink(request, identity, action):
        """
        generate magic link and send email/sms.

        parameter:
            action : can be anyone ["verify", "delete", "forgot_password", "login"]
        """
        token_generator = api_settings.GENERATE_VERIFY_TOKEN_CLASS()      # object
        
        identity_obj = get_identityObj(identity)                          # Here, identity_obj should be only email/phoneNumber
        user = identity_obj.user
        identity_obj.set_verification_sent()

        protocol = 'https' if request.is_secure() else 'http'
        domain = get_current_site(request).domain
        uid = http.urlsafe_base64_encode(encoding.force_bytes(user.pk))
        identity_id = http.urlsafe_base64_encode(encoding.force_bytes(identity_obj.pk))
        token = token_generator.make_token(user)

        view_dct = {
            "verify" : "verify_magiclink",
            "delete" : "delete_identity_verify_magiclink",
            "forgot_password" : "forgot_password_verify_magiclink",
            "session_login" : "session_login_magiclink",
            "jwt_token_login" : "jwt_token_obtain_pair_magiclink"
        }
        viewname = view_dct.get(action)
        if not viewname:
            raise djangoValidationError('enter valid action from ["verify", "delete", "forgot_password", "login"].')

        magic_link = f"{protocol}://{domain}" + reverse(viewname, kwargs={'uidb64' : uid, 'iidb64' : identity_id, 'token' : token}) 
        login_type = find_logintype(identity)

        # sending email
        if login_type == LOGIN_TYPE['email']:
            email_class = api_settings.SEND_EMAIL_CLASS
            email_class.send_email(
                subject = "Email Verification",
                to = identity_obj.email,
                template = 'email_verify.html',
                username = user.username,
                magic_link = magic_link,
                magic_link_verification = True,
                expiry_time = settings.PASSWORD_RESET_TIMEOUT//60
            )

        # sending sms
        elif login_type == LOGIN_TYPE['phoneNumber']:
            sms_class = api_settings.SEND_SMS_CLASS
            sms_class.send_sms(
                host = "9112398322",
                to = identity_obj.phoneNumber,
                message = f"Hi {user.username}, \n Your Magic link is {magic_link}. \n Please do not share it with anyone."
            )


# ======================================================== Validate_OTP class ========================================================
class Validate_OTP:
    @staticmethod
    def validate_otp(identity, otp, update_timestamp=True):
        """
        parameter :
            update_timestamp - True for verify_identity and forgot_password
                               False for login and delete_identity (i.e. identity should be verified prior login and deleting identity)

        Helper function to validate otp for -
        1. signup
        2. add_identity
        3. delete_identity
        4. forgot_password 
        5. authentication and login
        """
        identity_obj = get_identityObj(identity)              # Here, identity_obj should be only email/phoneNumber
        user = identity_obj.user
        
        # for login and deleting identity, identity should be verified prior
        if (update_timestamp is False) and (not identity_obj.is_verified):
            raise djangoValidationError("Identity should be verified prior login and deleting identity.", code="invalid_otp")

        if otp != user.otp:
            print(type(otp), type(user.otp))
            raise djangoValidationError("Invalid OTP. Kindly enter the exact OTP send to your email or phoneNumber.", code="invalid_otp")

        otp_class = api_settings.GENERATE_VERIFY_OTP_CLASS
        otp_verified = otp_class.verify_otp(user.secret, otp)
        
        user.otp=None
        user.secret = None
        user.save(update_fields=['otp', 'secret'])
        identity_obj.verification_sent = False
        identity_obj.save(update_fields=['verification_sent'])

        if otp_verified:
            if (not identity_obj.is_verified) and update_timestamp:
                identity_obj.verified_at = timezone.now()
                identity_obj.save(update_fields=['verified_at'])
            return True
        else:
            raise djangoValidationError("Given otp is expired. Kindly request for another OTP.", code="otp_expired")


# ======================================================== Validate_Magiclink class ========================================================
class Validate_Magiclink:
    @staticmethod
    def validate_magiclink(uidb64, iidb64, token, update_timestamp=True):
        """
        parameter :
            update_timestamp - True for verify_identity and forgot_password
                               False for login and delete_identity (i.e. identity should be verified prior login and deleting identity)

        Helper function to validate magiclink for -
        1. signup
        2. add_identity
        3. delete_identity
        4. forgot_password 
        5. authentication and login
        """
        try:
            user_id = encoding.force_str(http.urlsafe_base64_decode(uidb64))
            identity_id = encoding.force_str(http.urlsafe_base64_decode(iidb64))
            
            user_id = int(user_id)
            identity_id = int(identity_id)
        except:
            raise djangoValidationError("Invalid link.")

        user = get_user_model().objects.filter(pk=user_id).first()
        if user is None:
            raise djangoValidationError(f"No user with Id: {user_id} found")
        
        from ..models import UserIdentity
        identity_obj = UserIdentity.objects.filter(pk=identity_id).first()
        if identity_obj is None:
            raise djangoValidationError(f"No identity with Id: {identity_id} found")
        
        if str(user.username) != str(identity_obj.user.username):
            raise djangoValidationError("This identity is not registered with your account.")

        # for login and deleting identity, identity should be verified prior
        if (update_timestamp is False) and (not identity_obj.is_verified):
            raise djangoValidationError("Identity should be verified prior login and deleting identity.", code="invalid_link")

        token_generator = api_settings.GENERATE_VERIFY_TOKEN_CLASS()      # object
        is_token_valid = token_generator.check_token(user, token)
        
        if identity_obj.verification_sent:        
            identity_obj.verification_sent = False
            identity_obj.save(update_fields=['verification_sent'])

        if is_token_valid:
            if (not identity_obj.is_verified) and update_timestamp:
                identity_obj.verified_at = timezone.now()
                identity_obj.save(update_fields=['verified_at'])
            return True
        else:
            raise djangoValidationError("Given magic link is expired or not valid.")
