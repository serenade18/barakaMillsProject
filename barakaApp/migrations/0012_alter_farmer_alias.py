# Generated by Django 4.2.1 on 2024-12-28 18:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('barakaApp', '0011_alter_farmer_alias'),
    ]

    operations = [
        migrations.AlterField(
            model_name='farmer',
            name='alias',
            field=models.CharField(max_length=255, null=True, unique=True),
        ),
    ]
