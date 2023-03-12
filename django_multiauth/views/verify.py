from django.core.exceptions import ValidationError as djangoValidationError
from django.utils import http, encoding

from rest_framework.response import Response
from rest_framework import status, views

from . import ViewBase
from ..settings import api_settings


# ======================================================== VerifyOtp view ==========================================================
class VerifyOtpView(ViewBase):
    """
    Verify the otp & Validate the identity on which otp is send.

    request body_params:
        identity : can be username/ email/ phoneNumber
        otp
    """
    _serializer_class = api_settings.VERIFY_OTP_SERIALIZER

    def check_configuration(self):
        assert api_settings.OTP_VERIFICATION, "settings.OTP_VERIFICATION must be set to True."

    def post(self, request, *args, **kwargs):
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
            return Response({"status" : "success"}, status=status.HTTP_200_OK)

verify_otp_view = VerifyOtpView.as_view()


# ======================================================== VerifyMagicLink view ==========================================================
class VerifyMagicLinkView(views.APIView):
    """
    Verify the magiclink & validate the identity on which magiclink is send.
    """
    def check_configuration(self):
        assert api_settings.MAGIC_LINK_VERIFICATION, "settings.MAGIC_LINK_VERIFICATION must be set to True."

    def get(self, request, *args, **kwargs):
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
            return Response({"status" : "success"}, status=status.HTTP_200_OK)

verify_magiclink_view = VerifyMagicLinkView.as_view()
