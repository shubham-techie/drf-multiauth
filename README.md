## Multiway Authentication System
A simple authentication plugin for Django REST Framework which will allow user to signup and login via multiple identities like username, email or phoneNumber. \
The app is built using **Django REST framework**. \
It can be used as an **API** to authenticate user and authorize requests.

### Features :
1. Authentication system is built such that user can **login either using password or otp or activation link**.
2. User can **add multiple emails and phoneNumber** in their account, so that they can **register/login via any of the combination**.
3. **Email and phoneNumber verification** on adding, removing, reset-password.
4. **2FA** available via any *Authenticator app*.

### Installation guide :
```
pip install git+https://github.com/shubham-techie/drf-multiauth.git
```

### Available endpoints : 
```
1. signup/with-password/
2. signup/with-otp/
3. signup/with-magiclink/

4. add-identity/with-otp/
5. add-identity/with-magiclink/

6. delete-identity/verify-otp/
7. delete-identity/verify-magiclink/<str:uidb64>/<str:iidb64>/<str:token>/
8. delete-unverified-identity/

9. forgot-password/verify-otp/
10. forgot-password/verify-magiclink/<str:uidb64>/<str:iidb64>/<str:token>/

11. resend-otp/
12. resend-magiclink/

13. verify-otp/
14. verify-magiclink/<str:uidb64>/<str:iidb64>/<str:token>/

15. login/                                                                  (with password as well as OTP)
16. login/verify-magiclink/<str:uidb64>/<str:iidb64>/<str:token>/

17. create-token/                                                           (with password as well as OTP)
18. create-token/verify-magiclink/<str:uidb64>/<str:iidb64>/<str:token>/
19. refresh-token/
20. verify-token/

21. session-logout/
22. jwt-logout/

23. change-username/
24. change-password/

25. set-primary-identity/

26. 2fa/enable/generate-otp/
27. 2fa/enable/verify-otp/
28. 2fa/disable/
29. 2fa/verify-factor/<str:uid>/? token=<token>&user_backend=<backend>
```

### settings.py :
Add below custom settings in main Django project settings.py configuration file.

```
INSTALLED_APPS = [
    .
    .
    'django_multiauth',                
    'rest_framework',                  
    'rest_framework_simplejwt',        
]

AUTH_USER_MODEL = 'django_multiauth.User'

AUTHENTICATION_BACKENDS = [
    'django_multiauth.backends.UsernamePaswordBackend',
    'django_multiauth.backends.EmailPasswordBackend',
    'django_multiauth.backends.MobilePasswordBackend',
    'django_multiauth.backends.UsernameOtpBackend',
    'django_multiauth.backends.EmailOtpBackend',
    'django_multiauth.backends.MobileOtpBackend',
    'django_multiauth.backends.MagicLinkBackend'
]

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = '<email_with which_you_send_verification_links>'
EMAIL_HOST_PASSWORD = '<email_password>'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ]
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=10),
    'USER_ID_FIELD' : 'userprofile_id'
}

DJANGO_MULTIAUTH = {
}

# for OTP and magic_link
PASSWORD_RESET_TIMEOUT = 900 # in secs   
```

### Demo videos :
1. **Overview of all api-endpoints** : https://www.loom.com/share/652688bc449d4feabcb066c1f679895c

2. **demo for signup, verify, resend endpoints** : https://www.loom.com/share/39bce7bef7fe4d8bbc92f53a4b889d30

3. **demo for login, create-token, refresh-token, logout, jwt-logout** :  https://www.loom.com/share/649b6b91f5d24335a3944bd4640f4671

4. **demo for add and delete identity** : https://www.loom.com/share/a8a73f4868074b6c970c2e70da5eb69d

5. **demo for forgot-password, change-username and password, set-primary-identity** : https://www.loom.com/share/72822cbdfff045538f6c87d195cf7ba7

6. **demo for 2fa** : https://www.loom.com/share/3224b466a63c4b9f8e39af58220f3050
