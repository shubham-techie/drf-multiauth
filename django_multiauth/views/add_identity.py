from rest_framework import status, permissions
from rest_framework.response import Response

from . import ViewBase
from ..settings import api_settings


# ======================================================== View Mixins ========================================================
class AddIdentity_ViewMixin(ViewBase):
    """
    Add email or phoneNumber to logged in user account.
    """
    _serializer_class = api_settings.ADD_IDENTITY_SERIALIZER
    permission_classes = [permissions.IsAuthenticated]

    with_otp=False
    with_magiclink=False

    def post(self, request, *args, **kwargs):
        self.check_configuration() 

        serializer = self.get_serializer(data=request.data)     
        serializer.is_valid(raise_exception=True)
        identity_obj = serializer.save()

        identity = identity_obj.identity

        if self.with_otp:
            otp_dispatch_class = api_settings.SEND_OTP_CLASS
            otp_dispatch_class.send_otp(identity)

        elif self.with_magiclink:
            magiclink_dispatch_class = api_settings.SEND_MAGICLINK_CLASS
            magiclink_dispatch_class.send_magiclink(request, identity, action="verify")
        else:
            assert self.with_otp or self.with_magiclink, "either with_otp or with_magiclink must be set to True."
        return Response({
                **serializer.data, 
                **{"status" : "success",
                    "message" : "identity added successfully.", 
                    "DeliveryStatus": ("OTP" if self.with_otp else "Magic link") + " delivered successfully."
                }}, status=status.HTTP_201_CREATED)


# ======================================================== AddIdentity_Otp view ==========================================================
class AddIdentity_Otp_View(AddIdentity_ViewMixin):
    """
    Add email/ phoneNumber to logged in user account with OTP.

    request body_params:
        identity
    """
    with_otp=api_settings.OTP_VERIFICATION
    with_magiclink=False

    def check_configuration(self):
        assert api_settings.OTP_VERIFICATION, "settings.OTP_VERIFICATION must be set to True."

add_identity_otp_view = AddIdentity_Otp_View.as_view()


# ======================================================== AddIdentity_MagicLink view ==========================================================
class AddIdentity_MagicLink_View(AddIdentity_ViewMixin):
    """
    Add email/ phoneNumber to logged in user account with magiclink.

    request body_params:
        identity
    """
    with_otp=False
    with_magiclink=api_settings.MAGIC_LINK_VERIFICATION

    def check_configuration(self):
        assert api_settings.MAGIC_LINK_VERIFICATION, "settings.MAGIC_LINK_VERIFICATION must be set to True."

add_identity_magiclink_view = AddIdentity_MagicLink_View.as_view()


# # ======================================================== AddPhoneNumberOtp view ==========================================================
# class AddPhoneNumberOtpView(AddIdentity_ViewMixin):
#     """
#     Add phoneNumber to logged in user account with OTP.

#     request body_params:
#         phoneNumber
#     """
#     _serializer_class = api_settings.ADD_PHONENUMBER_SERIALIZER
#     with_otp=api_settings.OTP_VERIFICATION
#     with_magiclink=False

#     def check_configuration(self):
#         assert api_settings.OTP_VERIFICATION, "settings.OTP_VERIFICATION must be set to True."

# add_phoneNumber_otp_view = AddPhoneNumberOtpView.as_view()


# # ======================================================== AddPhoneNumberMagicLink view ==========================================================
# class AddPhoneNumberMagicLinkView(AddIdentity_ViewMixin):
#     """
#     Add phoneNumber to logged in user account with magiclink.

#     request body_params:
#         phoneNumber
#     """
#     _serializer_class = api_settings.ADD_PHONENUMBER_SERIALIZER
#     with_otp=False
#     with_magiclink=api_settings.MAGIC_LINK_VERIFICATION

#     def check_configuration(self):
#         assert api_settings.MAGIC_LINK_VERIFICATION, "settings.MAGIC_LINK_VERIFICATION must be set to True."

# add_phoneNumber_magiclink_view = AddPhoneNumberMagicLinkView.as_view()
