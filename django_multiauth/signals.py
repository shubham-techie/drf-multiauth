from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model

from .models import UserProfile

@receiver(pre_save, sender=get_user_model())
def create_userprofile(sender, instance, **kwargs):
    try:
        instance.userprofile
    except UserProfile.DoesNotExist:
        instance.userprofile = UserProfile.objects.create()
