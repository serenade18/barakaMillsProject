# Generated by Django 4.2.16 on 2025-01-10 07:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('barakaApp', '0015_alter_payments_kilos'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='milled',
            name='farmer_name',
        ),
    ]
