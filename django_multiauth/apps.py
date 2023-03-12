from django.apps import AppConfig

class DjangoMultiauthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_multiauth'

    def ready(self) -> None:
        import django_multiauth.signals
