# Generated by Django 4.2.1 on 2024-12-28 18:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('barakaApp', '0009_alter_farmer_name_alter_farmer_phone_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='farmer',
            name='farmer_number',
            field=models.CharField(max_length=255, null=True, unique=True),
        ),
    ]
