from django.db import models

from apps.core import APP_LABEL
from apps.farmers.models import Farmer
from apps.machines.models import Machine


# Milling model
class Milled(models.Model):
    id = models.AutoField(primary_key=True)
    farmer_id = models.ForeignKey(Farmer, on_delete=models.CASCADE)
    machine_id = models.ForeignKey(Machine, on_delete=models.CASCADE)
    kgs = models.CharField(max_length=255)
    output = models.CharField(max_length=255)
    price = models.CharField(max_length=255)
    amount = models.CharField(max_length=255)
    mill_date = models.DateField()
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    class Meta:
        app_label = APP_LABEL
