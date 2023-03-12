from django.utils.http import urlsafe_base64_decode as decode_string, base36_to_int
from django.contrib.auth.models import update_last_login
from django.contrib.auth import get_user_model, login

from rest_framework.response import Response
from rest_framework import generics, status, permissions, views

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

from ..settings import api_settings
import pyotp


# ========================================================  Enable_2FA_GenerateOTP view ==========================================================
class Enable_2FA_GenerateOTP_View(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, *args, **kwargs):
        """
        Generate OTP to enable 2FA by storing the base_32 secret in user_id.
        """
        user = request.user
        user.mfa_secret_key = pyotp.random_base32()
        user.save(update_fields = ['mfa_secret_key'])
        return Response({"base32_secret_key" : user.mfa_secret_key}, status=status.HTTP_200_OK)

enable_2fa_generate_otp_view = Enable_2FA_GenerateOTP_View.as_view()


# ========================================================  Enable_2FA_VerifyOTP view ==========================================================
class Enable_2FA_VerifyOTP_View(views.APIView):
    permission_classes = [permissions.IsAuthenticated]
        
    def post(self, request, *args, **kwargs):
        """
        Verify the OTP generated from authenticator app by user to enable 2FA.

        request body_params:
            otp
        """
        otp = request.data.get('otp', None)
        if otp is None:
            return Response({'otp' : ['This field is required.']}, status=status.HTTP_400_BAD_REQUEST)
        else:
            try:
                otp = int(otp)
            except ValueError:
                return Response({"status" : "fail", "message" : "OTP should be an integer value."}, status=status.HTTP_400_BAD_REQUEST)


        user = request.user
        totp = pyotp.TOTP(user.mfa_secret_key)
        otp_verified = totp.verify(otp)

        if not otp_verified:
            return Response({'status' : "fail", 'message' : "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
        
        user.mfa_enabled = True
        user.save(update_fields = ['mfa_enabled'])
        return Response({'status' : 'success', 'mfa_enabled' : 'True'}, status=status.HTTP_200_OK)

enable_2fa_verify_otp_view = Enable_2FA_VerifyOTP_View.as_view()


# ========================================================  Disable_2FA view ==========================================================
class Disable_2FA_View(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        user.mfa_enabled = False
        user.mfa_secret_key = None
        user.save(update_fields = ['mfa_enabled', 'mfa_secret_key'])
        return Response({'status' : 'success', 'mfa_enabled' : 'False'}, status=status.HTTP_200_OK)

disable_2fa_view = Disable_2FA_View.as_view()


# ========================================================  VerifyFactor_2FA view ==========================================================
class VerifyFactor_2FA_View(views.APIView):

    def post(self, request, *args, **kwargs):
        """
        Verify the OTP generated from authenticator app by user 
        after posting user credentials to login_session or jwt_token_creation if 2FA is enabled.

        "uid" as url path.

        query_params:
            token : timestamp_b36 + (encoded "session" or "jwt")
            user_backend (required for only session login type)

        request body_params:
            otp
        """
        if request.user.is_authenticated:
            return Response({
                "status" : "fail",
                "message" : "You are already logged in (i.e either your session or jwt is still alive)."
                }, status.HTTP_400_BAD_REQUEST)

        # getting otp from request body
        otp = request.data.get('otp', None)
        if not otp:
            return Response({'otp' : ['This fields is required.']}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            otp = int(otp)
        except ValueError:
            return Response({"status" : "fail", "message" : "OTP should be an integer value."}, status=status.HTTP_401_UNAUTHORIZED)


        # getting token from query_params
        token = request.GET.get('token')
        if token is None:
            return Response({'token' : ['This is required as query parameter.']}, status=status.HTTP_401_UNAUTHORIZED)
        try:                                            # Parse the token
            ts_b36, en_login_type = token.split("-")
        except ValueError:
            return Response({'status' : "fail", 'message' : "Invalid token."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return Response({'status' : "fail", 'message' : "Invalid timestamp in token."}, status=status.HTTP_401_UNAUTHORIZED)

        login_type = decode_string(en_login_type)      # rehashing
        login_type = login_type.decode()            # converting bytes to string
    
        # getting user from url_path
        user_id = kwargs.get('uid')
        user = get_user_model().objects.filter(pk=user_id).first()
        if user is None:
            return Response({"status" : "fail", "message" : f"No user with Id: {user_id} found."}, status=status.HTTP_401_UNAUTHORIZED)
        
        totp = pyotp.TOTP(user.mfa_secret_key)
        otp_verified = totp.verify(otp)
        if not otp_verified:
            return Response({'status' : "fail", 'message' : "Invalid OTP."}, status=status.HTTP_401_UNAUTHORIZED)
        
        # time within which otp from authenticator app is to be entered for 2FA
        from ..utils import get_timestamp
        if (get_timestamp() - ts) > api_settings.TOKEN_LIFETIME_2FA:
            return Response({'status' : "fail", 'message' : "Token expired. Try again."}, status=status.HTTP_401_UNAUTHORIZED)


        # creating session
        if login_type == "session":
            user_backend = request.GET.get('user_backend')      # getting user_backend from query_params
            if user_backend is None:
                return Response({'user_backend' : ['This field is required.']}, status=status.HTTP_401_UNAUTHORIZED)
            login(request, user, user_backend)                # creating session_id in cookies
            update_last_login(None, user) 
            return Response({'status' : 'success', 'otp_verified' : 'True', "loginStatus" : "Login successful."}, status=status.HTTP_200_OK)
        
        # creating jwt_token
        elif login_type=="jwt":
            try:
                refresh_obj = RefreshToken.for_user(user)
            except TokenError as err:
                raise InvalidToken(err.args[0])
            else:
                data = {"refresh" : str(refresh_obj), "access" : str(refresh_obj.access_token)}
                update_last_login(None, user)
                return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({"status" : "fail", "message" : "Invalid login_type in token."}, status=status.HTTP_401_UNAUTHORIZED)

verify_factor_2fa_view = VerifyFactor_2FA_View.as_view()
