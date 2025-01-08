# Generated by Django 4.2.1 on 2024-12-28 13:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('barakaApp', '0003_remove_milled_refferal_farmer_refferal'),
    ]

    operations = [
        migrations.AddField(
            model_name='farmer',
            name='secondary_phone',
            field=models.CharField(default=0, max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='payments',
            name='payment_mode',
            field=models.CharField(choices=[(1, 'Cash'), (2, 'Mpesa'), (3, 'Bank'), (4, 'KCB'), (5, 'Equity'), (6, 'Others')], max_length=255),
        ),
    ]