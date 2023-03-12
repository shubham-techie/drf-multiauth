from django.utils import http, encoding
from django.core.exceptions import ValidationError as djangoValidationError

from rest_framework.response import Response
from rest_framework import status

from . import ViewBase
from ..settings import api_settings


# ======================================================== ForgotPassword_VerifyOtp view ==========================================================
class ForgotPassword_VerifyOtp_View(ViewBase):
    """
    Retrieve or Reset the password when user does not remember password.

    request body_params:
        identity : can be username/ email/ phoneNumber
        otp
        new_password1 : new password
        new_password2 : re-enter new password
    """
    _serializer_class = api_settings.FORGOT_PASSWORD_VERIFY_OTP_SERIALIZER

    def check_configuration(self):
        assert api_settings.OTP_VERIFICATION, "settings.OTP_VERIFICATION must be set to True."

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response({
                "status" : "fail",
                "message" : "You are logged in. Try changing the password."
            }, status.HTTP_400_BAD_REQUEST)

        self.check_configuration()
        
        serializer = self.get_serializer(data=request.data)      
        serializer.is_valid(raise_exception=True)
        identity = serializer.validated_data.get('identity')
        otp = serializer.validated_data.get('otp')

        validate_otp_class = api_settings.VALIDATE_OTP_CLASS
        try:
            validate_otp_class.validate_otp(identity, otp)
        except djangoValidationError as err:
            return Response({
                "status" : "fail",
                "message": err.args[0]
            }, status=status.HTTP_401_UNAUTHORIZED) 
        else:
            serializer.save()               # reseting the password
            return Response({"status" : "success", "message" : "Password reset successfully."}, status=status.HTTP_200_OK)

forgot_password_verify_otp_view = ForgotPassword_VerifyOtp_View.as_view()


# ======================================================== ForgotPassword_VerifyMagicLink view ==========================================================
class ForgotPassword_VerifyMagicLink_View(ViewBase):
    """
    Retrieve or Reset the password when user does not remember password.

    request body_params:
        new_password1 : new password
        new_password2 : re-enter new password
    """
    _serializer_class = api_settings.FORGOT_PASSWORD_MAGICLINK_SERIALIZER
    
    def check_configuration(self):
        assert api_settings.MAGIC_LINK_VERIFICATION, "settings.MAGIC_LINK_VERIFICATION must be set to True."

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response({
                "status" : "fail",
                "message" : "You are logged in. Try changing the password."
            }, status.HTTP_400_BAD_REQUEST)

        self.check_configuration()
        
        uidb64 = kwargs.get('uidb64')
        iidb64 = kwargs.get('iidb64')
        token = kwargs.get('token')

        validate_magiclink_class = api_settings.VALIDATE_MAGICLINK_CLASS
        try:
            validate_magiclink_class.validate_magiclink(uidb64, iidb64, token)
        except djangoValidationError as err:
            return Response({
                "status" : "fail", 
                "message": err.args[0] 
            }, status=status.HTTP_401_UNAUTHORIZED)  
        else:
            serializer = self.get_serializer(data=request.data)      
            serializer.is_valid(raise_exception=True)

            from django.contrib.auth import get_user_model
            user_id = encoding.force_str(http.urlsafe_base64_decode(uidb64))
            user = get_user_model().objects.filter(pk=user_id).first()

            password = serializer.validated_data.get('password')
            user.password = password
            user.save(update_fields=['password'])
            return Response({"status" : "success", "message" : "Password reset successfully."}, status=status.HTTP_200_OK)

forgot_password_verify_magiclink_view = ForgotPassword_VerifyMagicLink_View.as_view()
