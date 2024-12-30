# Generated by Django 4.2.1 on 2024-12-28 16:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('barakaApp', '0006_payments_amount'),
    ]

    operations = [
        migrations.AlterField(
            model_name='payments',
            name='payment_mode',
            field=models.CharField(choices=[(1, 'Cash'), (2, 'Mpesa'), (3, 'KCB'), (4, 'Equity'), (5, 'Almanis Tier A'), (6, 'Almanis Tier B'), (7, 'Others')], max_length=255),
        ),
    ]
