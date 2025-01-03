# Generated by Django 4.2.16 on 2024-11-21 10:08

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='Farmer',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('alias', models.CharField(max_length=255, null=True)),
                ('farmer_number', models.CharField(max_length=255, unique=True)),
                ('name', models.CharField(max_length=255, unique=True)),
                ('phone', models.CharField(max_length=255, unique=True)),
                ('added_on', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Machine',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('added_on', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Milled',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('farmer_name', models.CharField(max_length=255)),
                ('kgs', models.CharField(max_length=255)),
                ('output', models.CharField(max_length=255)),
                ('price', models.CharField(max_length=255)),
                ('amount', models.CharField(max_length=255)),
                ('refferal', models.CharField(max_length=255, null=True)),
                ('mill_date', models.DateField()),
                ('added_on', models.DateTimeField(auto_now_add=True)),
                ('farmer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='barakaApp.farmer')),
                ('machine_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='barakaApp.machine')),
            ],
        ),
        migrations.CreateModel(
            name='OTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('otp', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='Payments',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('payment_mode', models.CharField(choices=[(1, 'Cash'), (2, 'Mpesa'), (3, 'Bank'), (4, 'Barter Trade'), (5, 'Promo'), (6, 'Compensation'), (7, 'Top-up')], max_length=255)),
                ('payment', models.CharField(max_length=255)),
                ('added_on', models.DateTimeField(auto_now_add=True)),
                ('farmer_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='barakaApp.farmer')),
                ('milling_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='barakaApp.milled')),
            ],
        ),
        migrations.CreateModel(
            name='UserAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('email', models.EmailField(max_length=255, unique=True)),
                ('name', models.CharField(max_length=255)),
                ('phone', models.CharField(max_length=255)),
                ('user_type', models.CharField(choices=[('admin', 'Admin'), ('sales', 'Sales'), ('accounts', 'Accounts'), ('hybrid', 'Hybrid')], default='sales', max_length=20)),
                ('is_active', models.BooleanField(default=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('added_on', models.DateTimeField(auto_now_add=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
