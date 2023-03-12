from django.db import models
from django.apps import apps

from .utils import LOGIN_TYPE, find_logintype, generate_unique_username


# ====================================================== Model Manager ======================================================

# =================================================== User Manager ===================================================
class UserManager(models.Manager):
    def _create_user(self, username=None, password=None, userprofile=None, **extra_fields):
        """
        method to create User Model object.
        If username or password is not entered, then system generated credentials will be automatic created.
        """

        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)

        # if user registers using email or phoneNumber, then system generated unique username is automatic created.
        if not username:
            username = generate_unique_username()

        # fetching userModel
        GlobalUserModel = apps.get_model(               
            self.model._meta.app_label, 
            self.model._meta.object_name
        )

        user = self.model(
            userprofile=userprofile, 
            username=username, 
            password=password,              # if user enters password, then password will be validated 
            **extra_fields                  # by full_clean() in save() method & then it will be hashed. 
        )                                   # Else if system generated unusable password will be created in save() method.
        user.save(using=self._db)
        return user


    def create_user(self, login_name=None, password=None, userprofile=None, **extra_fields):
        """
        Common method to be called to register user with either username, email or phoneNumber.
        """

        if not login_name:
            raise ValueError("Login name cannot be blank!! Enter either username, email or phoneNumber.")
        
        login_type = find_logintype(login_name)

        # creating user with username
        if login_type == LOGIN_TYPE['username']:
            print("User instance is being created.....")
            user = self._create_user(
                username=login_name,
                password=password, 
                userprofile=userprofile, 
                **extra_fields
            )
            return user

        # creating user with email
        elif login_type == LOGIN_TYPE['email']:
            print("UserEmail instance is being created.....")
            UserEmail = apps.get_model(self.model._meta.app_label, 'UserEmail')

            user = self._create_user(
                username=None,
                password=password, 
                userprofile=userprofile, 
                **extra_fields
            )
            email = UserEmail.objects.create(user=user, email=login_name)
            return user

        # creating user with phoneNumber
        elif login_type == LOGIN_TYPE['phoneNumber']:
            print("UserMobile instance is being created.....")
            UserMobile = apps.get_model(self.model._meta.app_label, 'UserMobile')

            user = self._create_user(
                username=None,
                password=password, 
                userprofile=userprofile, 
                **extra_fields
            )
            phoneNumber = UserMobile.objects.create(user=user, phoneNumber=login_name)
            return user


    def create_superuser(self, username=None, password=None, userprofile=None, **extra_fields):
        """
        method to register admin user.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        return self.create_user(
            login_name=username, 
            password=password, 
            userprofile=userprofile, 
            **extra_fields
        )


    def create(self, login_name=None, password=None, userprofile=None, **extra_fields):
        """
        helper method to call specific method to register user, if bymistake create() method is called.
        """
        return self.create_user(
            login_name=login_name, 
            password=password, 
            userprofile=userprofile, 
            **extra_fields
        )
        

    def get_by_natural_key(self, username):
        return self.get(**{self.model.USERNAME_FIELD: username})

   
# =================================================== UserEmail Manager ===================================================
class UserEmailManager(models.Manager):
    def create(self, user=None, email=None, **extra_fields):
        """
        method to add email of user.
        """
        if not email or not user:
            raise ValueError("Kindly enter both email as well as user...")

        email = self.model(user=user, email=email, **extra_fields)
        email.save()

        if not user.useridentity.filter(is_primary=True).count():
            email.set_primary()
        return email


# =================================================== UserMobile Manager ===================================================
class UserMobileManager(models.Manager):
    def create(self, user=None, phoneNumber=None, **extra_fields):
        """
        method to add phoneNumber of user.
        """
        if not phoneNumber or not user:
            raise ValueError("Kindly enter both phoneNumber as well as user...")

        phoneNumber = self.model(user=user, phoneNumber=phoneNumber, **extra_fields)
        phoneNumber.save()

        if not user.useridentity.filter(is_primary=True).count():
            phoneNumber.set_primary()
        return phoneNumber
