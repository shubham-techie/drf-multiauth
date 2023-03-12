from django.utils import http, encoding
from django.core.exceptions import ValidationError as djangoValidationError

from rest_framework import status, permissions, generics
from rest_framework.response import Response

from . import ViewBase
from ..settings import api_settings
from ..utils import get_identityObj

# ======================================================== View Mixins ========================================================
class DeleteIdentity_ViewMixin(ViewBase):
    """
    send OTP/ magiclink to delete email or phoneNumber.
    """
    _serializer_class = api_settings.DELETE_IDENTITY_SERIALIZER
    permission_classes = [permissions.IsAuthenticated]

    with_otp=False
    with_magiclink=False

    def post(self, request, *args, **kwargs):
        self.check_configuration()

        serializer = self.get_serializer(data=request.data)      
        serializer.is_valid(raise_exception=True)
        identity = serializer.validated_data.get('identity')

        if self.with_otp:
            otp_dispatch_class = api_settings.SEND_OTP_CLASS
            otp_dispatch_class.send_otp(identity)

        elif self.with_magiclink:
            magiclink_dispatch_class = api_settings.SEND_MAGICLINK_CLASS
            magiclink_dispatch_class.send_magiclink(request, identity, action="delete")
        else:
            assert self.with_otp or self.with_magiclink, "either with_otp or with_magiclink must be set to True."
        return Response({
                **serializer.data, 
                **{"status" : "success",
                    "message": ("OTP" if self.with_otp else "Magic link") + " delivered successfully."
                }}, status=status.HTTP_200_OK)
        

# ======================================================== DeleteIdentity_SendOtp view ==========================================================
class DeleteIdentity_SendOtp_View(DeleteIdentity_ViewMixin):
    """
    send OTP to delete email or phoneNumber.

    request body_params:
        identity
    """
    with_otp=api_settings.OTP_VERIFICATION
    with_magiclink=False

    def check_configuration(self):
        assert api_settings.OTP_VERIFICATION, "settings.OTP_VERIFICATION must be set to True."

delete_identity_send_otp_view = DeleteIdentity_SendOtp_View.as_view()


# ======================================================== DeleteIdentity_SendMagicLink view ==========================================================
class DeleteIdentity_SendMagicLink_View(DeleteIdentity_ViewMixin):
    """
    send OTP/ magiclink to delete email or phoneNumber.

    request body_params:
        identity
    """
    with_otp=False
    with_magiclink=api_settings.MAGIC_LINK_VERIFICATION

    def check_configuration(self):
        assert api_settings.MAGIC_LINK_VERIFICATION, "settings.MAGIC_LINK_VERIFICATION must be set to True."

delete_identity_send_magiclink_view = DeleteIdentity_SendMagicLink_View.as_view()


# ======================================================== DeleteIdentity_VerifyOtp view ==========================================================
class DeleteIdentity_VerifyOtp_View(ViewBase):
    """
    Deletes the identity by Verifing the otp & Validating the identity on which otp is send.

    request body_params:
        identity : can be email/ phoneNumber
        otp
    """
    _serializer_class = api_settings.VERIFY_OTP_SERIALIZER
    permission_classes = [permissions.IsAuthenticated]

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
            validate_otp_class.validate_otp(identity, otp, update_timestamp=False)
        except djangoValidationError as err:
            return Response({
                "status" : "fail",
                "message": err.args[0]
            }, status=status.HTTP_401_UNAUTHORIZED)    
        else:        
            identity_obj = get_identityObj(identity)
            identity_obj.delete()
            return Response({"status" : "success", "message" : "identity deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

delete_identity_verify_otp_view = DeleteIdentity_VerifyOtp_View.as_view()


# ======================================================== DeleteIdentity_VerifyMagicLink view ==========================================================
class DeleteIdentity_VerifyMagicLink_View(generics.GenericAPIView):
    """
    Deletes the identity by verifing the magiclink & validating the identity on which magiclink is send.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def check_configuration(self):
        assert api_settings.MAGIC_LINK_VERIFICATION, "settings.MAGIC_LINK_VERIFICATION must be set to True."

    def get(self, request, *args, **kwargs):
        self.check_configuration()
        
        uidb64 = kwargs.get('uidb64')
        iidb64 = kwargs.get('iidb64')
        token = kwargs.get('token')

        validate_magiclink_class = api_settings.VALIDATE_MAGICLINK_CLASS
        try:
            validate_magiclink_class.validate_magiclink(uidb64, iidb64, token, update_timestamp=False)
        except djangoValidationError as err:
            return Response({
                "status" : "fail", 
                "message": err.args[0] 
            }, status=status.HTTP_401_UNAUTHORIZED)    
        else:
            from ..models import UserIdentity
            identity_id = encoding.force_str(http.urlsafe_base64_decode(iidb64))
            identity_obj = UserIdentity.objects.filter(pk=identity_id).first()
            identity_obj.delete()
            return Response({"status" : "success", "message" : "identity deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

delete_identity_verify_magiclink_view = DeleteIdentity_VerifyMagicLink_View.as_view()


# ======================================================== Delete_Unverified_Identity view ==========================================================
class Delete_Unverified_Identity_View(ViewBase):
    """
    deletes the unverified identities that user might have added to his account due to wrong input and is univerified.

    request body_params:
        identity
    """
    _serializer_class = api_settings.DELETE_IDENTITY_SERIALIZER
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)      
        serializer.is_valid(raise_exception=True)
        identity = serializer.validated_data.get('identity')
        identity_obj = get_identityObj(identity)

        if identity_obj.is_verified:
            return Response({
                "status" : "fail",
                "message" : "This identity is verified. Kindly contact the admin if you no longer have access to this identity."
                }, status=status.HTTP_400_BAD_REQUEST)

        identity_obj.delete()
        return Response({"status" : "success", "message" : "identity deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

delete_unverified_identity_view = Delete_Unverified_Identity_View.as_view()