from rest_framework.response import Response
from rest_framework import permissions, status

from . import ViewBase
from ..settings import api_settings


# ======================================================== ChangeUsername view ==========================================================
class ChangeUsernameView(ViewBase):
    """
    To update username.

    request body_params:
        new_username
    """
    _serializer_class = api_settings.CHANGE_USERNAME_SERIALIZER
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, *args, **kwargs):
        serializer = self.get_serializer(instance=request.user, data=request.data)      
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "status" : "success",
            "message" : "username changed successfully.",
            "new_username" :user.username
        }, status=status.HTTP_200_OK)

change_username_view = ChangeUsernameView.as_view()


# ======================================================== ChangePassword view ==========================================================
class ChangePasswordView(ViewBase):
    """
    To update password.

    request body_params:
        old_password 
        new_password1 : new password
        new_password2 : re-enter new password
    """
    _serializer_class = api_settings.CHANGE_PASSWORD_SERIALIZER
    permission_classes = [permissions.IsAuthenticated]

    def put(self, request, *args, **kwargs):
        serializer = self.get_serializer(instance=request.user, data=request.data)      
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "status" : "success",
            "message" : "password changed successfully.",
            "new_username" :user.username
        }, status=status.HTTP_200_OK)

change_password_view = ChangePasswordView.as_view()