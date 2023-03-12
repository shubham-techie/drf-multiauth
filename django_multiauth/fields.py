from django.db import models


# =================================================== Mixins ===================================================

# using this mixin with any CharField type (like CharField, EmailField or any other) to convert data to lowercase.
class CaseInsensitive_FieldMixin:
    """
    Field Mixin to make string to lowercase.
    """
    def to_python(self, value):
        value = super().to_python(value)
        return value.lower() if isinstance(value, str) else value
    

# using this mixin with any CharField type to convert empty data to None, so that it can be saved as null in DB.
class EmptyStringToNone_FieldMixin:
    """
    Override CharField type to make empty string as None.
    """
    def get_db_prep_value(self, value, *args, **kwargs):
        if value == '':
            value = None
        return super().get_db_prep_value(value, *args, **kwargs)



# ============================================== Customized Fields ==============================================

class _CharField(
    CaseInsensitive_FieldMixin, 
    EmptyStringToNone_FieldMixin, 
    models.CharField
    ):
    """
    Case Insensitive CharField to convert empty string value to None.
    """
    pass


class _EmailField(
    CaseInsensitive_FieldMixin, 
    EmptyStringToNone_FieldMixin, 
    models.EmailField
    ):
    """
    Case Insensitive EmailField to convert empty string value to None.
    """
    pass


class EmptyStringToNone_CharField(
    EmptyStringToNone_FieldMixin, 
    models.CharField
    ):
    """
    CharField to convert empty string value to None.
    """
    pass