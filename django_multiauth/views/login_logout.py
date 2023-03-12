from django.urls import reverse
from django.contrib.auth.models import update_last_login
from django.contrib.auth import authenticate, login, logout
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode as encode_string, int_to_base36

from rest_framework.response import Response
from rest_framework import status, permissions, views
from rest_framework.exceptions import AuthenticationFailed as drfAuthenticationFailed

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

from . import ViewBase
from ..settings import api_settings
from ..exceptions import AuthenticationFailed as djangoAuthenticationFailed


def get_callback_url(request, user, login_type):
    protocol = 'https' if request.is_secure() else 'http'
    domain = get_current_site(request).domain
    url = f"{protocol}://{domain}" + reverse('verify_factor_2fa', args=[str(user.pk)])

    login_type = login_type.encode()         # converting string to bytes
    en_login_type = encode_string(login_type)  # hashing
    
    from ..utils import get_timestamp
    ts = get_timestamp()
    ts_b36 = int_to_base36(ts)
    token = ts_b36 +'-' + en_login_type
    
    query_params = f'?token={token}&user_backend={user.backend}'
    return url + query_params, token

# ======================================================== SessionLogin_PasswordOTP view ==========================================================
class SessionLogin_PasswordOTP_View(ViewBase):
    """
    Session login view with password or otp.

    request body_params:
        identity : can be username/ email/ phoneNumber
        password or OTP
    """
    _serializer_class = api_settings.AUTHENTICATION_SERIALIZER

    def check_configuration(self):
        assert api_settings.SESSION_AUTHENTICATION, "settings.SESSION_AUTHENTICATION must be set to True."
  
    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response({
                "status" : "fail",
                "message" : "You are already logged in (i.e either your session or jwt is still alive)."
                }, status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)      
        serializer.is_valid(raise_exception=True)
        identity = serializer.validated_data.get('identity')
        password = serializer.validated_data.get('password')
        otp = serializer.validated_data.get('otp')

        self.check_configuration()
        if otp:
            assert api_settings.OTP_VERIFICATION, "settings.OTP_VERIFICATION must be set to True."

        try:
            user = authenticate(request, username=identity, password=password, otp=otp)
        except djangoAuthenticationFailed as err:
            raise drfAuthenticationFailed({"status": err.args[0]})
        else:
            if user:
                if user.mfa_enabled:
                    login_type = "session"
                    url, token = get_callback_url(request, user, login_type)
                    return Response({
                        **serializer.data,
                        **{"status" : "success",
                        "message" : "user credentials verifed successfully.",
                        "action required" : "MFA is required for this user.",
                        "base32_secret_key" : user.mfa_secret_key,
                        "callback_url" : url,
                        "user_id" : user.id,
                        "user_backend" : user.backend,
                        "token" : token
                        }}, status=status.HTTP_200_OK)
                else:
                    login(request, user)                # creating session_id in cookies
                    update_last_login(None, user) 
                    return Response({**serializer.data, **{"status" : "success", "message" : "Login successful."}}, status=status.HTTP_200_OK)
            else:   
                return Response({
                    "status" : "fail", 
                    "message" : "Entered Username or email or phoneNumber DoesNotExist."
                }, status=status.HTTP_401_UNAUTHORIZED) 

session_login_password_otp_view = SessionLogin_PasswordOTP_View.as_view()


# ======================================================== SessionLogin_MagicLink view ==========================================================
class SessionLogin_MagicLink_View(views.APIView):
    """
    Session login view with magiclink.
    """
    
    def check_configuration(self):
        assert api_settings.SESSION_AUTHENTICATION, "settings.SESSION_AUTHENTICATION must be set to True."
        assert api_settings.MAGIC_LINK_VERIFICATION, "settings.MAGIC_LINK_VERIFICATION must be set to True."

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response({
                "status" : "fail",
                "message" : "You are already logged in (i.e either your session or jwt is still alive)."
                }, status.HTTP_400_BAD_REQUEST)

        self.check_configuration()
        
        uidb64 = kwargs.get('uidb64')
        iidb64 = kwargs.get('iidb64')
        token = kwargs.get('token')

        try:
            temp_username = uidb64 + '-' + iidb64
            user = authenticate(request, username=temp_username, token=token)
        except djangoAuthenticationFailed as err:
            raise drfAuthenticationFailed({"status": err.args[0]})
        else:
            if user:
                if user.mfa_enabled:
                    login_type = "session"
                    url, mfa_token = get_callback_url(request, user, login_type)
                    return Response({
                        "status" : "success",
                        "message" : "magic link verifed successfully.",
                        "action required" : "MFA is required for this user.",
                        "base32_secret_key" : user.mfa_secret_key,
                        "callback_url" : url,
                        "user_id" : user.id,
                        "user_backend" : user.backend,
                        "token" : mfa_token
                        }, status=status.HTTP_200_OK)
                else:
                    login(request, user)                # creating session_id in cookies
                    update_last_login(None, user) 
                    return Response({"status" : "success", "message" : "Login successful."}, status=status.HTTP_200_OK)
            else:   
                return Response({
                    "status" : "fail", 
                    "message" : "Entered Username or email or phoneNumber DoesNotExist."
                }, status=status.HTTP_401_UNAUTHORIZED) 

session_login_magiclink_view = SessionLogin_MagicLink_View.as_view()


# ======================================================== JWT_TokenObtainPair_PasswordOTP view ==========================================================
class JWT_TokenObtainPair_PasswordOTP_View(ViewBase):
    """
    JWT token creation for authorizing request with password or otp.

    request body_params:
        identity : can be username/ email/ phoneNumber
        password or OTP
    """
    _serializer_class = api_settings.AUTHENTICATION_SERIALIZER

    def check_configuration(self):
        assert api_settings.JWT_AUTHENTICATION, "settings.JWT_AUTHENTICATION must be set to True."

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response({
                "status" : "fail",
                "message" : "You are already logged in (i.e either your session or jwt is still alive)."
                }, status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)      
        serializer.is_valid(raise_exception=True)
        identity = serializer.validated_data.get('identity')
        password = serializer.validated_data.get('password')
        otp = serializer.validated_data.get('otp')

        self.check_configuration()
        if otp:
            assert api_settings.OTP_VERIFICATION, "settings.OTP_VERIFICATION must be set to True."

        try:
            user = authenticate(request, username=identity, password=password, otp=otp)
        except djangoAuthenticationFailed as err:
            raise drfAuthenticationFailed({"status": err.args[0]})
        else:
            if user:
                if user.mfa_enabled:
                    login_type = "jwt"
                    url, token = get_callback_url(request, user, login_type)
                    return Response({
                        **serializer.data,
                        **{"status" : "success",
                        "message" : "user credentials verifed successfully.",
                        "action required" : "MFA is required for this user.",
                        "base32_secret_key" : user.mfa_secret_key,
                        "callback_url" : url,
                        "user_id" : user.id,
                        "token" : token
                        }}, status=status.HTTP_200_OK)
                else:                                                               # creating jwt token.
                    try:
                        refresh_obj = RefreshToken.for_user(user)
                    except TokenError as err:
                        raise InvalidToken(err.args[0])
                    else:
                        data = {"refresh" : str(refresh_obj), "access" : str(refresh_obj.access_token)}
                        update_last_login(None, user)
                        return Response(data, status=status.HTTP_200_OK)
            else:   
                return Response({
                    "status" : "fail", 
                    "message" : "Entered Username or email or phoneNumber DoesNotExist."
                }, status=status.HTTP_401_UNAUTHORIZED) 

jwt_token_obtain_pair_password_otp_view = JWT_TokenObtainPair_PasswordOTP_View.as_view()


# ======================================================== JWT_TokenObtainPair_MagicLink view ==========================================================
class JWT_TokenObtainPair_MagicLink_View(views.APIView):
    """
    JWT token creation for authorizing request with magiclink.
    """
    
    def check_configuration(self):
        assert api_settings.JWT_AUTHENTICATION, "settings.JWT_AUTHENTICATION must be set to True."
        assert api_settings.MAGIC_LINK_VERIFICATION, "settings.MAGIC_LINK_VERIFICATION must be set to True."

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return Response({
                "status" : "fail",
                "message" : "You are already logged in (i.e either your session or jwt is still alive)."
                }, status.HTTP_400_BAD_REQUEST)

        self.check_configuration()
        
        uidb64 = kwargs.get('uidb64')
        iidb64 = kwargs.get('iidb64')
        token = kwargs.get('token')

        try:
            temp_username = uidb64 + '-' + iidb64
            user = authenticate(request, username=temp_username, token=token)
        except djangoAuthenticationFailed as err:
            raise drfAuthenticationFailed({"status": err.args[0]})
        else:
            if user:
                if user.mfa_enabled:
                    login_type = "jwt"
                    url, mfa_token = get_callback_url(request, user, login_type)
                    return Response({
                        "status" : "success",
                        "message" : "magic link verifed successfully.",
                        "action required" : "MFA is required for this user.",
                        "base32_secret_key" : user.mfa_secret_key,
                        "callback_url" : url,
                        "user_id" : user.id,
                        "token" : mfa_token
                        }, status=status.HTTP_200_OK)
                else:                                                               # creating jwt token.
                    try:
                        refresh_obj = RefreshToken.for_user(user)
                    except TokenError as err:
                        raise InvalidToken(err.args[0])
                    else:
                        data = {"refresh" : str(refresh_obj), "access" : str(refresh_obj.access_token)}
                        update_last_login(None, user)
                        return Response(data, status=status.HTTP_200_OK)
            else:   
                return Response({
                    "status" : "fail", 
                    "message" : "Entered Username or email or phoneNumber DoesNotExist."
                }, status=status.HTTP_401_UNAUTHORIZED) 

jwt_token_obtain_pair_magiclink_view = JWT_TokenObtainPair_MagicLink_View.as_view()


# ======================================================== SessionLogout view ==========================================================
class SessionLogoutView(views.APIView):
    """
    Session logout using GET request.
    """
    permission_classes = [permissions.IsAuthenticated]

    def check_configuration(self):
        assert api_settings.SESSION_AUTHENTICATION, "settings.SESSION_AUTHENTICATION must be set to True."
       
    def get(self, request, *args, **kwargs):
        self.check_configuration()
        logout(request)
        return Response({"status" : "success", "message" : "Session deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

session_logout_view = SessionLogoutView.as_view()


# ======================================================== JWTLogout view ==========================================================
class JWTLogoutView(ViewBase):
    """
    JWT logout using POST request.

    request body_params:
        refresh
    """
    _serializer_class = api_settings.LOGOUT_SERIALIZER
    permission_classes = [permissions.IsAuthenticated]

    def check_configuration(self):
        assert api_settings.JWT_AUTHENTICATION, "settings.JWT_AUTHENTICATION must be set to True."

    def post(self, request, *args, **kwargs):
        """
        Logout for jwt.
        """
        self.check_configuration()
        
        serializer = self.get_serializer(data=request.data)      
        serializer.is_valid(raise_exception=True)
        refresh = serializer.validated_data.get('refresh')

        try:
            RefreshToken(refresh).blacklist()
        except TokenError as err:
            raise InvalidToken(err.args[0])
        else:
            return Response({"status" : "success", "message" : "JWT blacklisted successfully."}, status=status.HTTP_204_NO_CONTENT)

jwt_logout_view = JWTLogoutView.as_view()
