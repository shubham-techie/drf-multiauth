from rest_framework.response import Response
from rest_framework import status

from . import ViewBase
from ..settings import api_settings


# ======================================================== ResendOtp view ==========================================================
class ResendOtpView(ViewBase):
    """
    Sends otp to email/ phoneNumber.

    request body_params:
        identity : can be username/ email/ phoneNumber.
        (For username, primary email/phoneNumber should be there.)
    """
    _serializer_class = api_settings.RESEND_OTP_MAGICLINK_SERIALIZER

    def check_configuration(self):
        assert api_settings.OTP_VERIFICATION, "settings.OTP_VERIFICATION must be set to True."

    def post(self, request, *args, **kwargs):
        self.check_configuration()

        serializer = self.get_serializer(data=request.data)      
        serializer.is_valid(raise_exception=True)
        identity = serializer.validated_data.get('identity')
        
        otp_dispatch_class = api_settings.SEND_OTP_CLASS
        otp_dispatch_class.send_otp(identity)
        return Response({
            **serializer.data, 
            **{"status": "success"
            }}, status=status.HTTP_200_OK)

resend_otp_view = ResendOtpView.as_view()


# ========================================================  ResendMagicLink view ==========================================================
class ResendMagicLinkView(ViewBase):
    """
    Sends magic_link to email/ phoneNumber.

    request body_params:
        identity : can be username/ email/ phoneNumber.
        (For username, primary email/phoneNumber should be there.)
    """
    _serializer_class = api_settings.RESEND_OTP_MAGICLINK_SERIALIZER
    action = "verify"

    def check_configuration(self):
        assert api_settings.MAGIC_LINK_VERIFICATION, "settings.MAGIC_LINK_VERIFICATION must be set to True."

    def post(self, request, *args, **kwargs):
        self.check_configuration()

        serializer = self.get_serializer(data=request.data)      
        serializer.is_valid(raise_exception=True)
        identity = serializer.validated_data.get('identity')
            
        magiclink_dispatch_class = api_settings.SEND_MAGICLINK_CLASS
        magiclink_dispatch_class.send_magiclink(request, identity, action=self.action)
        return Response({
            **serializer.data, 
            **{"status": "success"
            }}, status=status.HTTP_200_OK)
        
resend_magiclink_view = ResendMagicLinkView.as_view()


# ========================================================  SessionLogin_SendMagicLink view ==========================================================
class SessionLogin_SendMagicLinkView(ResendMagicLinkView):
    action = "session_login"
session_login_send_magiclink_view = SessionLogin_SendMagicLinkView.as_view()


# ========================================================  JWT_Token_SendMagicLink view ==========================================================
class JWT_Token_SendMagicLinkView(ResendMagicLinkView):
    action = "jwt_token_login"
jwt_token_send_magiclink_view = JWT_Token_SendMagicLinkView.as_view()


# ========================================================  ForgotPassword_SendMagicLink view ==========================================================
class ForgotPassword_SendMagicLinkView(ResendMagicLinkView):
    action = "forgot_password"
forgot_password_send_magiclink_view = ForgotPassword_SendMagicLinkView.as_view()
