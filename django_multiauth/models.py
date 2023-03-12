from django.db import models
from django.utils.crypto import salted_hmac
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import password_validation
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.hashers import check_password, make_password, is_password_usable

from .exceptions import IdentityModelObjectError, NoPrimaryIdentity
from .managers import UserManager, UserEmailManager, UserMobileManager
from .fields import _CharField, _EmailField, EmptyStringToNone_CharField
from .validators import validate_username, validate_phoneNumber


# ======================================================== Model Mixins ========================================================

class ValidateAndSave_ModelMixin:
    """
    Mixin to run field validators and apply changes according to FieldMixin before saving object to DB.
    """
    def save(self, *args, **kwargs):
        self.full_clean()                  # validating fields
        return super(ValidateAndSave_ModelMixin, self).save(*args, **kwargs)


# =========================================================== Models ===========================================================


# =================================================== UserProfile Model ===================================================

class UserProfile(ValidateAndSave_ModelMixin, models.Model):
    """
    Model to store user profile details.
    """
    class Gender(models.TextChoices):
        MALE = 'male', _('Male')
        FEMALE = 'female', _('Female')
        TRANSGENDER = 'transgender', _('Transgender')
        NONE = '', _('None/ Not to specify')

    first_name = _CharField(max_length=100, blank=True, null=True)
    last_name = _CharField(max_length=100, blank=True, null=True)
    bio = _CharField(max_length=300, blank=True, null=True)
    dob = models.DateField(max_length=10, blank=True, null=True)
    address = _CharField(max_length=500, blank=True, null=True)
    gender = _CharField(
        max_length=15,
        blank=True, 
        null=True, 
        choices=Gender.choices, 
        default = Gender.NONE
    )

    class Meta:
        verbose_name_plural = 'UserProfile'
        db_table = "user_profile"

    def __str__(self):
        obj_displayname = None

        if (self.first_name is None) and (self.last_name is None):
            try:
                obj_displayname = self.user.username
            except:
                obj_displayname =  "object"
        else:
            obj_displayname = self.first_name +" "+ self.last_name
        return obj_displayname
    


# =================================================== User Model ===================================================

class User(PermissionsMixin):
    """
    Default user model.
    """
    userprofile = models.OneToOneField(
        UserProfile,
        blank=True,
        on_delete = models.CASCADE, 
        primary_key=True
    )

    username = _CharField(
        max_length=200, 
        unique=True, 
        blank=True,
        validators=[validate_username],
        help_text = _(
            "Required. " 
            "200 characters or fewer. "
            "Should not be only whitespace/s or only numeric. "
            "Should not contain special character - '@' "
            "Should not start with '+' symbol. "
            "Case insensitive username i.e. it will always be saved as lowercase."
            )
    )

    password = EmptyStringToNone_CharField(
        max_length=128, 
        blank=True, 
        # validators=[password_validation.validate_password]             # password is validated in model manager while creating User object.
    )

    last_login = models.DateTimeField(blank=True, null=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default= False)  # overriding from Permissionmixin

    otp = models.IntegerField(null=True,blank=True)
    secret = EmptyStringToNone_CharField(max_length=70,blank=True,null=True)
    
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret_key = EmptyStringToNone_CharField(max_length=70,blank=True,null=True)

    REQUIRED_FIELDS = []
    USERNAME_FIELD = "username"

    objects = UserManager()

    class Meta:
        verbose_name_plural = 'User'
        db_table = "user"   
    
    def __str__(self):
        return self.username

    @property
    def id(self):
        return self.userprofile_id

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True

    def get_username(self):
        return self.username
        
    def validate_password(self, password):
        password_validation.validate_password(password)


    def set_password(self, raw_password):
        """
        hash the password.
        """
        self.password = make_password(raw_password)


    def set_unusable_password(self):
        """
        Set a value that will never be a valid hash
        """
        self.password = make_password(None)
    

    def has_usable_password(self):
        """
        Return False if set_unusable_password() has been called for this user i.e if password starts_with '!'
        """
        return is_password_usable(self.password)


    def check_password(self, raw_password):
        def setter(raw_password):
            """
            used to rehash the password if raw_password matches.
            """
            self.set_password(raw_password)
            self.save(update_fields=["password"])

        return check_password(raw_password, self.password, setter)
    

    def get_primary_identity(self):
        """
        Return primary email or phoneNumber if exists, else None.
        """
        if self.useridentity.filter(is_primary=True).count():
            identity_obj = self.useridentity.filter(is_primary=True).first()
            try:
                return identity_obj.get_EmailMobile_instance()
            except IdentityModelObjectError:
                raise IdentityModelObjectError(
                    "primary object has been set to non-existent email or phoneNumber. Kindly Reset your primary identity."
                )
        else:
            raise NoPrimaryIdentity("you do not have any primary email or phoneNumber set.")
        

    def get_session_auth_hash(self):
        """
        Return an HMAC of the password field.
        """
        key_salt = "django_multiauth.models.User.get_session_auth_hash"
        return salted_hmac(
            key_salt,
            self.password,
            algorithm="sha256",
        ).hexdigest()


    def save(self, *args, **kwargs):
        """
        run the field validators and apply custom field changes and then save the object.
        """
        update_fields = kwargs.get('update_fields', None)

        # validating fields only if new user is created or username is updated.
        if (update_fields is None) or ('username' in update_fields):
            self.full_clean()                                               
        
        # validating password if user has entered or when it is updated.
        if self.password:
            if (update_fields is None) or ('password' in update_fields):
                self.validate_password(self.password)

        # hash the password only if new user is created or when it is updated.
        if (update_fields is None) or ('password' in update_fields):
            self.set_password(self.password) if self.password else self.set_unusable_password()
       
        return super(User, self).save(*args, **kwargs)



# =================================================== UserIdentity Model ===================================================
class UserIdentity(models.Model):
    """
    Model to keep track of all email and phoneNumber of a user.
    Each instance is either UserEmail instance or UserMobile instance.
    """

    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='useridentity'           # to get all identities of any user object : run--> self.user.useridentity.all()                           
    )
    is_primary = models.BooleanField(default=False)                 
    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(default=None, null=True, blank=True)
    verification_sent = models.BooleanField(default=False)                    # to validate identity on which otp is sent
    
    
    class Meta:
        verbose_name_plural = 'UserIdentity'
        db_table = "user_identity"

    def __str__(self):
        if hasattr(self, 'useremail'):
            return (self.useremail.email) 
        elif hasattr(self, 'usermobile'):
            return (self.usermobile.phoneNumber)
        else:
            raise IdentityModelObjectError("Non-existent Identity model object is being accessed.")
    
    @property
    def is_verified(self):
        return bool(self.verified_at)
    
    @property
    def identity(self):
        return (self.useremail.email) if hasattr(self, 'useremail') else (self.usermobile.phoneNumber)
        
    def set_primary(self):
        """
        Set this identity's is_primary=True and all others to False for this user.
        """
      
        for identity in self.user.useridentity.all():
            if identity == self.user.useridentity.get(id=self.id):     # UserIdentity.objects.get(id=self.id)
                if not identity.is_primary:
                    identity.is_primary = True
                    identity.save(update_fields=['is_primary'])
            else:
                if identity.is_primary:
                    identity.is_primary = False
                    identity.save(update_fields=['is_primary'])
                    
        print("This identity is now set to primary.")


    # def set_primary(self):
    #     """
    #     to set one email and one phoneNumber to primary.
    #     """

    #     if hasattr(self, 'useremail'):
    #         self.useremail.set_primary()
    #     elif hasattr(self, 'usermobile'):
    #         self.usermobile.set_primary()
    #     else:
    #         raise IdentityModelObjectError("Non-existent Identity model object is being accessed.")
    
    
    def set_verification_sent(self):
        """
        Set this identity's verification_sent to True and all others to False for this user.
        """

        for identity in self.user.useridentity.all():
            if identity == self.user.useridentity.get(id=self.id):     # UserIdentity.objects.get(id=self.id)
                if not identity.verification_sent:
                    identity.verification_sent = True
                    identity.save(update_fields=['verification_sent'])
            else:
                if identity.verification_sent:
                    identity.verification_sent = False
                    identity.save(update_fields=['verification_sent'])
                    

    def get_EmailMobile_instance(self):
        """
        return UserEmail or UserMobile instance.
        """
        if hasattr(self, 'useremail'):
            return self.useremail
        elif hasattr(self, 'usermobile'):
            return self.usermobile
        else:
            raise IdentityModelObjectError("Non-existent Identity model object is being accessed.")


    def validate_instance(self):
        """
        called before saving to validate UserIdentity instance. It should be either UserEmail instance or UserMobile instance.
        """
        from .models import UserEmail, UserMobile
        if isinstance(self, UserEmail) or  isinstance(self, UserMobile):  
            return True
        raise IdentityModelObjectError("You cannot create UserIdentity object. Enter only email or phoneNumber.")


    def save(self, *args, **kwargs):
        update_fields = kwargs.get('update_fields', None)

        # checking that UserIdentity object is not being created, when UserEmail or UserMobile objects are created.
        if update_fields is None:        
            self.validate_instance()
        return super(UserIdentity, self).save(*args, **kwargs)



# =================================================== UserEmail Model ===================================================

class UserEmail(ValidateAndSave_ModelMixin, UserIdentity):
    email = _EmailField(
        max_length=254, 
        unique=True
    )

    objects = UserEmailManager()

    class Meta:
        verbose_name_plural = 'UserEmail'
        db_table = "user_email"

    def __str__(self):
        return self.email
    
    # def set_primary(self):
    #     """
    #     Set this email's is_primary to True and all others email's for this user to False.
    #     """
    #     for email in self.__class__.objects.filter(user=self.user):
    #         if email == self:
    #             if not email.is_primary:
    #                 email.is_primary = True
    #                 email.save()
    #         else:
    #             if email.is_primary:
    #                 email.is_primary = False
    #                 email.save()
    #     return self


    
# =================================================== UserMobile Model ===================================================

class UserMobile(ValidateAndSave_ModelMixin, UserIdentity):
    phoneNumber = EmptyStringToNone_CharField(
        max_length = 20, 
        unique = True, 
        validators = [validate_phoneNumber]
    )
    
    objects = UserMobileManager()

    class Meta:
        verbose_name_plural = 'UserMobile'
        db_table = "user_phone"

    def __str__(self):
        return self.phoneNumber

    # def set_primary(self):
    #     """
    #     Set this phoneNumber's is_primary to True and all others phoneNumber's for this user to False.
    #     """
    #     for phoneNumber in self.__class__.objects.filter(user=self.user):
    #         if phoneNumber == self:
    #             if not phoneNumber.is_primary:
    #                 phoneNumber.is_primary = True
    #                 phoneNumber.save()
    #         else:
    #             if phoneNumber.is_primary:
    #                 phoneNumber.is_primary = False
    #                 phoneNumber.save()
    #     return self
