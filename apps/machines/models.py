from django.db import models

from apps.core import APP_LABEL


# Machine model
class Machine(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    class Meta:
        app_label = APP_LABEL
