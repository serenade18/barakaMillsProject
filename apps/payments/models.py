from django.db import models

from apps.core import APP_LABEL
from apps.farmers.models import Farmer
from apps.milling.models import Milled


# Payment model
class Payments(models.Model):
    choices = ((1, "Cash"), (2, "Mpesa"), (3, "KCB"), (4, "Equity"), (5, "Almanis Tier A"),\
               (6, "Almanis Tier B"), (7, "Others"))

    id = models.AutoField(primary_key=True)
    farmer_id = models.ForeignKey(Farmer, on_delete=models.CASCADE)
    payment_mode = models.CharField(choices=choices, max_length=255)
    kilos = models.CharField(max_length=255, default=0)
    payment = models.CharField(max_length=255)
    amount = models.CharField(max_length=255, default=0)
    price = models.CharField(max_length=255, default=2.50)
    receipt_number = models.CharField(max_length=255, default=0)
    milling_id = models.ForeignKey(Milled, on_delete=models.CASCADE)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    class Meta:
        app_label = APP_LABEL
