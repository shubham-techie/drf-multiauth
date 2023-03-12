from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.validators import validate_email
from django.core.exceptions import ObjectDoesNotExist, ValidationError as djangoValidationError
from django.contrib.auth.password_validation import validate_password

from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import UserEmail, UserMobile
from .utils import LOGIN_TYPE, find_logintype, get_identityObj
from .validators import validate_username, validate_phoneNumber
from .exceptions import NoPrimaryIdentity, IdentityModelObjectError


# =========================================================== Serializers ===========================================================

# =================================================== Signup_Otp_MagicLink Serializer ===================================================
class Signup_Otp_MagicLink_Serializer(serializers.Serializer):
    login_name = serializers.CharField(required=True, source="username")

    def validate_login_name(self, value):
        """
        To signup with OTP/ magiclink, login_name should be email or phoneNumber.
        """
        
        # first validate as email
        try:
            validate_email(value)
        except djangoValidationError:                         # if value doesn't looks like email, then next it'll be validated for phoneNumber
            pass                     
        else:                                                 # if it's valid email, then check for uniqueness and return the value
            if UserEmail.objects.filter(email=value).exists():
                raise serializers.ValidationError("Account with this email already exists.")
            return value
        
        # next validate as phoneNumber
        try:
            validate_phoneNumber(value)
        except djangoValidationError:                         # if value doesn't looks like phoneNumber, then it must be username
            pass                     
        else:                                                 # if it's valid phoneNumber, then check for uniqueness and return the value
            if UserMobile.objects.filter(phoneNumber=value).exists():
                raise serializers.ValidationError("Account with this phoneNumber already exists.")
            return value
        
        # Then login_name might be username, so raise ValidationError
        raise serializers.ValidationError("Enter only email or phoneNumber. OTP or Magic link cannot be send to username.")


    def create(self, validated_data):
        user = get_user_model().objects.create_user(
            login_name = validated_data['username'], 
            password = validated_data.get('password')
        )
        return user


# =================================================== SignupPassword Serializer ===================================================
class SignupPasswordSerializer(Signup_Otp_MagicLink_Serializer):
    password1 = serializers.CharField(
        style={'input_type': 'password'}, 
        required=True,
        write_only=True,
        validators=[validate_password],
        source="password"
    )
    password2 = serializers.CharField(
        style={'input_type': 'password'}, 
        required=True,
        write_only=True
    )

    def validate_login_name(self, value):
        """
        validate username/email/phoneNumber.
        """
        try:
            validate_email(value)
        except djangoValidationError:                         # if value doesn't looks like email, then next it'll be validated for phoneNumber
            pass                     
        else:                                                 # if it's valid email, then check for uniqueness and return the value
            if UserEmail.objects.filter(email=value).exists():
                raise serializers.ValidationError("Account with this email already exists.")
            return value
        
        # next validate as phoneNumber
        try:
            validate_phoneNumber(value)
        except djangoValidationError:                         # if value doesn't looks like phoneNumber, then it must be username
            pass                     
        else:                                                 # if it's valid phoneNumber, then check for uniqueness and return the value
            if UserMobile.objects.filter(phoneNumber=value).exists():
                raise serializers.ValidationError("Account with this phoneNumber already exists.")
            return value

        try:
            validate_username(value)
        except djangoValidationError as err:                  # if value is not valid username, then raise error
            raise serializers.ValidationError(err.args[0])
        else:                                                 # if it's valid username, then check for uniqueness and return the value
            if get_user_model().objects.filter(username=value).exists():
                raise serializers.ValidationError("Account with this username already exists.")
            return value


    def validate(self, attrs):
        """
        to validate both passwords is same.
        """
        if attrs.get('password') != attrs.get('password2'):
            raise serializers.ValidationError({"new_password" : "Both passwords must be same."})
        return attrs


# =================================================== Resend_Otp_MagicLink Serializer ===================================================
class Resend_Otp_MagicLink_Serializer(serializers.Serializer):
    identity = serializers.CharField(required=True)

    def validate_identity(self, value):
        """
        validating whether this identity object exists. if identity username, check if it has any primary email or phoneNumber.
        """
        try:
            get_identityObj(value)
        except ObjectDoesNotExist:                                          # this error is raised when identity does not exists in User, Useremail or UserMobile DB.
            raise serializers.ValidationError("entered email or phoneNumber does not exists in Database.")
        except (NoPrimaryIdentity, IdentityModelObjectError) as err:        # these errors are raised if identity is username.
            raise serializers.ValidationError(err.args[0])
        return value


# =================================================== VerifyOtp Serializer ===================================================
class VerifyOtpSerializer(serializers.Serializer):
    identity = serializers.CharField(required=True)
    otp = serializers.IntegerField(required=True)

    def validate_identity(self, value):
        """
        validating the identity on which otp is sent.
        """
        try:
            identity_obj = get_identityObj(value)
        except ObjectDoesNotExist:                                          # this error is raised when identity does not exists in User, Useremail or UserMobile DB.
            raise serializers.ValidationError("entered identity does not exists in Database.")
        except (NoPrimaryIdentity, IdentityModelObjectError) as err:        # these errors are raised if identity is username.
            raise serializers.ValidationError(err.args[0])
        else:                                                               # validating the identity on which otp is sent
            if not identity_obj.verification_sent:
                raise serializers.ValidationError("Kindly enter the same identity on which otp has been sent.")
        return value
        


# =================================================== AddIdentity Serializer ===================================================
class AddIdentitySerializer(serializers.Serializer):
    user = serializers.HiddenField(
        default=serializers.CurrentUserDefault()
    )
    identity = serializers.CharField(required=True)

    # email = serializers.EmailField(
    #     required=True,
    #     validators = [
    #         UniqueValidator(
    #             queryset=UserEmail.objects.all(), 
    #             message="Account with this email already exists."
    #     )])
    # phoneNumber = serializers.CharField(
    #     required=True, 
    #     validators = [
    #         validate_phoneNumber,
    #         UniqueValidator(
    #             queryset=UserMobile.objects.all(), 
    #             message="Account with this phoneNumber already exists."
    #     )])

    def validate_identity(self, value):
        """
        To add identity in user account, it should be email or phoneNumber.
        """
        
        # first validate as email
        try:
            validate_email(value)
        except djangoValidationError:                         # if value doesn't looks like email, then next it'll be validated for phoneNumber
            pass                     
        else:                                                 # if it's valid email, then check for uniqueness and return the value
            if UserEmail.objects.filter(email=value).exists():
                raise serializers.ValidationError("Account with this email already exists.")
            return value
        
        # next validate as phoneNumber
        try:
            validate_phoneNumber(value)
        except djangoValidationError:                         # if value doesn't looks like phoneNumber, then it must be username
            pass                     
        else:                                                 # if it's valid email, then check for uniqueness and return the value
            if UserMobile.objects.filter(phoneNumber=value).exists():
                raise serializers.ValidationError("Account with this phoneNumber already exists.")
            return value
        
        # Then login_name might be username, so raise ValidationError
        raise serializers.ValidationError("Enter only email or phoneNumber. OTP or Magic link cannot be send to username.")


    def save(self):
        return self.create(self.validated_data)

    def create(self, validated_data):
        identity = validated_data['identity']
        login_type = find_logintype(identity)
        identity_obj = None

        if login_type == LOGIN_TYPE['email']:
            identity_obj = UserEmail.objects.create(user=validated_data['user'], email=identity)
            print("done")
        elif login_type == LOGIN_TYPE['phoneNumber']:
            identity_obj = UserMobile.objects.create(user=validated_data['user'], phoneNumber=identity)
        return identity_obj


# =================================================== DeleteIdentity Serializer ===================================================
class DeleteIdentitySerializer(serializers.Serializer):
    user = serializers.HiddenField(
        default = serializers.CurrentUserDefault()
    )
    identity = serializers.CharField(required=True)


    def validate_identity(self, value):
        """
        To delete, identity should be email or phoneNumber.
        """

        # first validate as email
        try:
            validate_email(value)
            return value
        except djangoValidationError:                         # if value doesn't looks like email, then next it'll be validated for phoneNumber
            pass                     
        
        # next validate as phoneNumber
        try:
            validate_phoneNumber(value)
            return value
        except djangoValidationError:                         # if value doesn't looks like phoneNumber, then it must be username
            pass                     
        
        # Then login_name might be username, so raise ValidationError
        raise serializers.ValidationError("Enter only email or phoneNumber. OTP or Magic link cannot be send to username.")


    def validate(self, attrs):
        """
        validates identity whether it exists in DB and belongs to this user.
        """
        user = attrs.get('user')
        identity = attrs.get('identity')

        try:
            identity_obj = get_identityObj(identity)
        except ObjectDoesNotExist:                             # this error is raised when identity does not exists in User, Useremail or UserMobile DB.
            raise serializers.ValidationError({"identity" : "entered email or phoneNumber does not exists in Database."})
        else:
            if str(user.username) != str(identity_obj.user.username):
                raise serializers.ValidationError({"identity" : "This identity is not registered with your account."})
        return attrs

        
# =================================================== ForgotPassword_MagicLink Serializer ===================================================
class ForgotPassword_MagicLink_Serializer(serializers.Serializer):
    new_password1 = serializers.CharField(          
        style={'input_type': 'password'}, 
        required=True,
        write_only=True,
        validators=[validate_password],
        source="password"
    )
    new_password2 = serializers.CharField(              
        style={'input_type': 'password'}, 
        required=True,
        write_only=True
    )

    def validate(self, attrs):
        """
        to validate both passwords is same.
        """
        if attrs.get('password') != attrs.get('new_password2'):
            raise serializers.ValidationError({"new_password" : "Both passwords must be same."})
        return attrs


# =================================================== ForgotPassword_VerifyOtp Serializer ===================================================
class ForgotPassword_VerifyOtp_Serializer(VerifyOtpSerializer, ForgotPassword_MagicLink_Serializer):
    def create(self, validated_data):
        """
        reseting the password.
        """
        identity = validated_data.get('identity')
        password = validated_data.get('password')

        identity_obj = get_identityObj(identity)
        user = identity_obj.user

        user.password = password
        user.save(update_fields=['password'])
        return user
        

# =================================================== Authentication Serializer ===================================================
class AuthenticationSerializer(serializers.Serializer):
    identity = serializers.CharField(required=True)
    password = serializers.CharField(
        style={'input_type': 'password'}, 
        required=False, 
        write_only=True
    )
    otp = serializers.IntegerField(write_only=True, required=False)

    def validate(self, attrs):
        """
        method to validate atleast one of the field from password or otp is entered.
        """
        password = attrs.get('password')
        otp = attrs.get('otp')

        if not any([password, otp]):
            raise serializers.ValidationError({"password/otp" : ["This field may not be blank.", "Enter any one value from password or otp."]})
        return attrs


# =================================================== Logout Serializer ===================================================
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=True)


# =================================================== ChangeUsername Serializer ===================================================
class ChangeUsernameSerializer(serializers.Serializer):
    user = serializers.HiddenField(
        default = serializers.CurrentUserDefault()
    )
    new_username = serializers.CharField(
        required=True,
        source="username",
        validators = [
            validate_username,
            UniqueValidator(
                queryset=get_user_model().objects.all(),
                message="Account with this username already exists. Try entering another username."
        )])
    
    def validate(self, attrs):
        """
        validates that username is not same as previous.
        """
        if attrs.get('user').username == attrs.get('username'):
            raise serializers.ValidationError({"new_username" : "new username is same as previous. Kindly enter unique username."})
        return attrs

    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.save(update_fields=['username'])
        return instance


# =================================================== ChangePassword Serializer ===================================================
class ChangePasswordSerializer(serializers.Serializer):
    user = serializers.HiddenField(
        default = serializers.CurrentUserDefault()
    )
    old_password = serializers.CharField(
        style={'input_type': 'password'}, 
        required=True, 
        write_only=True
    )
    new_password1 = serializers.CharField(          
        style={'input_type': 'password'}, 
        required=True,
        write_only=True,
        validators=[validate_password],
        source="password"
    )
    new_password2 = serializers.CharField(              
        style={'input_type': 'password'}, 
        required=True,
        write_only=True
    )

    def validate(self, attrs):
        """
        validates that new_password is not same as previous.
        to validate both new_passwords are same.
        """
        user = attrs['user']
        old_password = attrs['old_password']
        new_password1 = attrs['password']
        new_password2 = attrs['new_password2']

        if not user.check_password(old_password):
            raise serializers.ValidationError({"old_password" : "invalid old password."})

        if attrs.get('password') != attrs.get('new_password2'):
            raise serializers.ValidationError({"new_password" : "Both new passwords must be same."})

        if old_password == new_password1:
            raise serializers.ValidationError({"new_password" : "new password is same as previous. Kindly enter new password."})
        return attrs


    def update(self, instance, validated_data):
        instance.password = validated_data.get('password', instance.password)
        instance.save(update_fields=['password'])
        return instance
