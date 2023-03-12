from django.utils.module_loading import import_string
from rest_framework import generics, response, status, permissions

from ..settings import api_settings
from ..utils import get_identityObj


"""
HTTP status code : 
    400 Bad Request is the status code to return when the form of the client request is not as the API expects.
    401 Unauthorized is the status code to return when the client provides no credentials or invalid credentials.
    403 Forbidden is the status code to return when a client has valid credentials but not enough privileges to perform an action on a resource.
"""

# ======================================================== View Mixins ========================================================
class ViewBase(generics.GenericAPIView):
    serializer_class = None
    _serializer_class = ""

    def get_serializer_class(self):
        """
        If serializer_class is set, use it directly. Otherwise get the class from settings.
        """
        if self.serializer_class:
            return self.serializer_class
        try:
            return import_string(self._serializer_class)
        except ImportError:
            message = "Could not import serializer '%s'" % self._serializer_class
            raise ImportError(message)

    def check_configuration(self):
        """
        checks for configurations.
        """


# ======================================================== SetPrimaryIdentity View ========================================================
class SetPrimaryIdentityView(ViewBase):
    _serializer_class = api_settings.DELETE_IDENTITY_SERIALIZER
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)      
        serializer.is_valid(raise_exception=True)
        identity = serializer.validated_data.get('identity')
        identity_obj = get_identityObj(identity)

        if identity_obj.is_primary:
            return response.Response({"status" : "fail", "message" : f"{identity} is already your primary identity."}, status=status.HTTP_400_BAD_REQUEST)
        identity_obj.set_primary()
        return response.Response({"status" : "success", "message" : f"{identity} is now set as primary."}, status=status.HTTP_200_OK)

set_primary_identity_view = SetPrimaryIdentityView.as_view()


# ========================================================  Imported View ========================================================
from .signup import (
    signup_password_view, 
    signup_otp_view, 
    signup_magiclink_view
)
from .resend import (
    resend_otp_view, 
    resend_magiclink_view,
    session_login_send_magiclink_view,
    jwt_token_send_magiclink_view,
    forgot_password_send_magiclink_view
)
from .verify import (
    verify_otp_view, 
    verify_magiclink_view
)
from .add_identity import (
    add_identity_otp_view,
    add_identity_magiclink_view
)
from .delete_identity import (
    delete_identity_send_otp_view,
    delete_identity_send_magiclink_view,
    delete_identity_verify_otp_view,
    delete_identity_verify_magiclink_view,
    delete_unverified_identity_view
)
from .forgot_password import (
    forgot_password_verify_otp_view,
    forgot_password_verify_magiclink_view
)
from .login_logout import (
    session_login_password_otp_view,
    session_login_magiclink_view, 
    jwt_token_obtain_pair_password_otp_view,
    jwt_token_obtain_pair_magiclink_view,
    session_logout_view,
    jwt_logout_view,
)
from .update_credentials import (
    change_username_view,
    change_password_view
)
from .mfa import(
    enable_2fa_generate_otp_view,
    enable_2fa_verify_otp_view,
    disable_2fa_view,
    verify_factor_2fa_view
)
