from django.urls import path, include
from . import views
from rest_framework_simplejwt import views as jwt_views


urlpatterns = [
    path('signup/with-password/',views.signup_password_view, name="signup_password"),
    path('signup/with-otp/',views.signup_otp_view, name="signup_otp"),
    path('signup/with-magiclink/',views.signup_magiclink_view, name="signup_magiclink"),

    path('resend-otp/', views.resend_otp_view, name="resend_otp"),
    path('resend-magiclink/', views.resend_magiclink_view, name="resend_magiclink"),

    path('verify-otp/', views.verify_otp_view, name="verify_otp"),
    path('verify-magiclink/<str:uidb64>/<str:iidb64>/<str:token>/', views.verify_magiclink_view, name="verify_magiclink"),

    path('add-identity/with-otp/', views.add_identity_otp_view, name="add_identity_otp"),
    path('add-identity/with-magiclink/', views.add_identity_magiclink_view, name="add_identity_magiclink"),

    path('delete-identity/send-otp/', views.delete_identity_send_otp_view, name="delete_identity_send_otp"),
    path('delete-identity/send-magiclink/', views.delete_identity_send_magiclink_view, name="delete_identity_send_magiclink"),
    path('delete-identity/verify-otp/', views.delete_identity_verify_otp_view, name="delete_identity_verify_otp"),
    path('delete-identity/verify-magiclink/<str:uidb64>/<str:iidb64>/<str:token>/', views.delete_identity_verify_magiclink_view, name="delete_identity_verify_magiclink"),
    path('delete-unverified-identity/', views.delete_unverified_identity_view, name="delete_unverified_identity"),
    
    path('forgot-password/send-otp/', views.resend_otp_view, name="forgot_password_send_otp"),
    path('forgot-password/send-magiclink/', views.forgot_password_send_magiclink_view, name="forgot_password_send_magiclink"),
    path('forgot-password/verify-otp/', views.forgot_password_verify_otp_view, name="forgot_password_verify_otp"),
    path('forgot-password/verify-magiclink/<str:uidb64>/<str:iidb64>/<str:token>/', views.forgot_password_verify_magiclink_view, name="forgot_password_verify_magiclink"),

    path('login/send-otp/', views.resend_otp_view, name="session_login_send_otp"),
    path('login/send-magiclink/', views.session_login_send_magiclink_view, name="session_login_send_magiclink"),
    path('login/', views.session_login_password_otp_view, name="session_login_password_otp"),
    path('login/verify-magiclink/<str:uidb64>/<str:iidb64>/<str:token>/', views.session_login_magiclink_view, name="session_login_magiclink"),

    path('create-token/send-otp/', views.resend_otp_view, name="jwt_token_send_otp"),
    path('create-token/send-magiclink/', views.jwt_token_send_magiclink_view, name="jwt_token_send_magiclink"),
    path('create-token/', views.jwt_token_obtain_pair_password_otp_view, name="jwt_token_obtain_pair_password_otp"),
    path('create-token/verify-magiclink/<str:uidb64>/<str:iidb64>/<str:token>/', views.jwt_token_obtain_pair_magiclink_view, name="jwt_token_obtain_pair_magiclink"),
    
    path('refresh-token/', jwt_views.token_refresh, name="refresh_token"),
    path('verify-token/', jwt_views.token_verify, name="verify_token"),

    path('logout/', views.session_logout_view, name="session_logout"),
    path('jwt-logout/', views.jwt_logout_view, name="jwt_logout"),

    path('change-username/', views.change_username_view, name="change_username"),
    path('change-password/', views.change_password_view, name="change_password"),

    path('set-primary-identity/', views.set_primary_identity_view, name="set_primary_identity"),

    path('2fa/enable/generate-otp/',views.enable_2fa_generate_otp_view, name="enable_2fa_generate_otp"),         
    path('2fa/enable/verify-otp/',views.enable_2fa_verify_otp_view, name="enable_2fa_verify_otp"),            
    path('2fa/disable/', views.disable_2fa_view, name="disable_2fa"),
    path('2fa/verify-factor/<str:uid>/', views.verify_factor_2fa_view, name="verify_factor_2fa"),

]
