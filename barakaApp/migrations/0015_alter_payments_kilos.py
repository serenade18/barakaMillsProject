# Generated by Django 4.2.16 on 2025-01-10 07:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('barakaApp', '0014_payments_kilos'),
    ]

    operations = [
        migrations.AlterField(
            model_name='payments',
            name='kilos',
            field=models.CharField(default=0, max_length=255),
        ),
    ]