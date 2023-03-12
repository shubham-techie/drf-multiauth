from rest_framework.response import Response
from rest_framework import status, generics

from . import ViewBase
from ..settings import api_settings
from ..utils import LOGIN_TYPE, find_logintype


# ======================================================== View Mixins ========================================================
class Signup_ViewMixin(ViewBase, generics.GenericAPIView):
    """
    Register user with login_name and password/otp/magic_link.
    """
    signup_otp=False          
    signup_magiclink=False

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response({
                "status" : "fail",
                "message" : "Cannot create account while you are logged in."
                }, status.HTTP_400_BAD_REQUEST)
        
        serializer = self.get_serializer(data=request.data)      # fetching respective serializer
        serializer.is_valid(raise_exception=True)
        serializer.save()                                        # creating user with either username, email, phoneNumber

        login_name = serializer.validated_data['username']
        login_type = find_logintype(login_name)

        # sending otp/link, if user has registered using email/phoneNumber
        if login_type != LOGIN_TYPE['username']:
            self.check_configuration()                               # check for otp and link configuration
            
            if self.signup_otp:
                otp_dispatch_class = api_settings.SEND_OTP_CLASS
                otp_dispatch_class.send_otp(login_name)

            elif self.signup_magiclink:
                magiclink_dispatch_class = api_settings.SEND_MAGICLINK_CLASS
                magiclink_dispatch_class.send_magiclink(request, login_name, action="verify")
            else:
                assert self.signup_otp or self.signup_magiclink, "either signup_otp or signup_magiclink must be set to True."
            print("Signup successful.")
            return Response({
                **serializer.data, 
                **{"status" : "success",
                    "message1" : "User registered successfully.", 
                    "message2": ("OTP" if self.signup_otp else "Magic link") + " delivered successfully."
                }}, status=status.HTTP_201_CREATED)
        else:
            print("Signup successful.")
            return Response({
                **serializer.data, 
                **{"status" : "success",
                    "message" : "User registered successfully."
                }}, status=status.HTTP_201_CREATED)



# ======================================================== SignupPassword view ==========================================================
class SignupPasswordView(Signup_ViewMixin):
    """
    Register user with login_name and password.

    request body_params:
        login_name : can be username/ email/ phoneNumber
        password1
        password2
    """
    _serializer_class = api_settings.SIGNUP_PASSWORD_SERIALIZER
    signup_otp = api_settings.DEFAULT_VERIFICATION['otp']
    signup_magiclink = api_settings.DEFAULT_VERIFICATION['magiclink']

    def check_configuration(self):
        msg = "anyone from api_settings.DEFAULT_VERIFICATION['otp'] or api_settings.DEFAULT_VERIFICATION['magiclink'] must be set to True."
        assert (self.signup_otp ^ self.signup_magiclink), msg

signup_password_view = SignupPasswordView.as_view()


# ======================================================== SignupOtp view ==========================================================
class SignupOtpView(Signup_ViewMixin):
    """
    Register user with login_name and otp.

    request body_params:
        login_name : can be email/ phoneNumber
    """
    _serializer_class = api_settings.SIGNUP_OTP_MAGICLINK_SERIALIZER
    signup_otp=api_settings.OTP_VERIFICATION
    signup_magiclink=False

    def check_configuration(self):
        assert api_settings.OTP_VERIFICATION, "settings.OTP_VERIFICATION must be set to True."

signup_otp_view = SignupOtpView.as_view()


# ======================================================== SignupMagicLink view ==========================================================
class SignupMagicLinkView(Signup_ViewMixin):
    """
    Register user with login_name and magic_link.

    request body_params:
        login_name : can be email/ phoneNumber
    """
    _serializer_class = api_settings.SIGNUP_OTP_MAGICLINK_SERIALIZER
    signup_otp=False
    signup_magiclink=api_settings.MAGIC_LINK_VERIFICATION

    def check_configuration(self):
        assert api_settings.MAGIC_LINK_VERIFICATION, "settings.MAGIC_LINK_VERIFICATION must be set to True."

signup_magiclink_view = SignupMagicLinkView.as_view()
  