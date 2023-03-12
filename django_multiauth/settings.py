from django.conf import settings
from django.test.signals import setting_changed
from django.utils.translation import gettext_lazy as _
from rest_framework.settings import APISettings


USER_SETTINGS = getattr(settings, "DJANGO_MULTIAUTH", None)

DEFAULTS = {
    "OTP_VERIFICATION" : True,
    "MAGIC_LINK_VERIFICATION" : True,
    "DEFAULT_VERIFICATION" : {              # default verification type for signup_password with email or phoneNumber
        "otp" : True, 
        "magiclink" : False
    },
    "SESSION_AUTHENTICATION" : True,
    "JWT_AUTHENTICATION" : True,
    # "EXPIRY_TIME" : 600,    # 10 mins       # for OTP and magic_link
    "OTP_LENGTH" : 6,
    "TOKEN_LIFETIME_2FA" : 300,   # in secs    # time within which otp from authenticator app is to be entered for 2FA

    "GENERATE_VERIFY_OTP_CLASS" : "django_multiauth.utils.Pyotp",
    "GENERATE_VERIFY_TOKEN_CLASS" : "django_multiauth.utils.TokenGenerator",
    "SEND_EMAIL_CLASS" : "django_multiauth.utils.Email",
    "SEND_SMS_CLASS" : "django_multiauth.utils.SMS",
    "SEND_OTP_CLASS" : "django_multiauth.utils.OTP_dispatch",
    "SEND_MAGICLINK_CLASS" : "django_multiauth.utils.MagicLink_dispatch",
    "VALIDATE_OTP_CLASS" : "django_multiauth.utils.Validate_OTP",
    "VALIDATE_MAGICLINK_CLASS" : "django_multiauth.utils.Validate_Magiclink",
    
    "SIGNUP_PASSWORD_SERIALIZER" : "django_multiauth.serializers.SignupPasswordSerializer",
    "SIGNUP_OTP_MAGICLINK_SERIALIZER" : "django_multiauth.serializers.Signup_Otp_MagicLink_Serializer",
    "RESEND_OTP_MAGICLINK_SERIALIZER" : "django_multiauth.serializers.Resend_Otp_MagicLink_Serializer",
    "VERIFY_OTP_SERIALIZER" : "django_multiauth.serializers.VerifyOtpSerializer",
    "ADD_IDENTITY_SERIALIZER" : "django_multiauth.serializers.AddIdentitySerializer",
    "DELETE_IDENTITY_SERIALIZER" : "django_multiauth.serializers.DeleteIdentitySerializer",
    "FORGOT_PASSWORD_MAGICLINK_SERIALIZER" : "django_multiauth.serializers.ForgotPassword_MagicLink_Serializer",
    "FORGOT_PASSWORD_VERIFY_OTP_SERIALIZER" : "django_multiauth.serializers.ForgotPassword_VerifyOtp_Serializer",
    "AUTHENTICATION_SERIALIZER" : "django_multiauth.serializers.AuthenticationSerializer",
    "LOGOUT_SERIALIZER" : "django_multiauth.serializers.LogoutSerializer",
    "CHANGE_USERNAME_SERIALIZER" : "django_multiauth.serializers.ChangeUsernameSerializer",
    "CHANGE_PASSWORD_SERIALIZER" : "django_multiauth.serializers.ChangePasswordSerializer",
    
}

IMPORT_STRINGS = [
    "GENERATE_VERIFY_OTP_CLASS",
    "GENERATE_VERIFY_TOKEN_CLASS",
    "SEND_EMAIL_CLASS",
    "SEND_SMS_CLASS",
    "SEND_OTP_CLASS",
    "SEND_MAGICLINK_CLASS",
    "VALIDATE_OTP_CLASS",
    "VALIDATE_MAGICLINK_CLASS"
]


api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)

def reload_api_settings(*args, **kwargs):  
    global api_settings
    setting, value = kwargs["setting"], kwargs["value"]

    if setting == "DJANGO_MULTIAUTH":
        api_settings = APISettings(value, DEFAULTS, IMPORT_STRINGS)
        

setting_changed.connect(reload_api_settings)
