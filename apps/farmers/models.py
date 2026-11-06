from django.db import models
from django.core.exceptions import ValidationError

from apps.core import APP_LABEL


# farmer model
class Farmer(models.Model):
    id = models.AutoField(primary_key=True)
    alias = models.CharField(max_length=255, null=True, unique=True)
    farmer_number = models.CharField(max_length=255, unique=True, null=True, blank=True)
    name = models.CharField(max_length=255, null=True,)
    phone = models.CharField(max_length=255, unique=True, null=True)
    secondary_phone = models.CharField(max_length=255, unique=True, null=True, blank=True)
    refferal = models.CharField(max_length=255, null=True, blank=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    class Meta:
        app_label = APP_LABEL

    def save(self, *args, **kwargs):
        # Normalize alias and farmer_number to lowercase
        if self.alias:
            self.alias = self.alias.lower()
        if self.farmer_number:
            self.farmer_number = self.farmer_number.lower()
        super().save(*args, **kwargs)

    def validate_unique(self, exclude=None):
        super().validate_unique(exclude)
        # Case-insensitive validation for alias
        if Farmer.objects.filter(alias__iexact=self.alias).exclude(pk=self.pk).exists():
            raise ValidationError({"alias": "A farmer with this alias already exists."})
        # Case-insensitive validation for farmer_number
        if Farmer.objects.filter(farmer_number__iexact=self.farmer_number).exclude(pk=self.pk).exists():
            raise ValidationError({"farmer_number": "A farmer with this number already exists."})
