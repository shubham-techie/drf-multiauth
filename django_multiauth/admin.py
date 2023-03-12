from django.contrib import admin
from . import models 

admin.site.register(models.UserProfile)
admin.site.register(models.User)
admin.site.register(models.UserIdentity)
admin.site.register(models.UserEmail)
admin.site.register(models.UserMobile)