from datetime import timedelta

from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db.models import AutoField
from django.utils import timezone
from django.core.exceptions import ValidationError


# Base user manager
class UserAccountManager(BaseUserManager):
    def create_user(self, email, name, phone, password=None, user_type=None):
        if not email:
            raise ValueError('Users must have an email address')

        if user_type not in ['sales', 'accounts', 'hybrid']:
            raise ValueError('Invalid user type. Must be sales, accounts, or hybrid')

        email = self.normalize_email(email)
        email = email.lower()

        user = self.model(
            email=email,
            name=name,
            user_type=user_type,
            phone=phone
        )

        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, name, phone, user_type=None, password=None):
        user = self.create_user(
            email=email,
            name=name,
            phone=phone,
            password=password,
            user_type=user_type or 'admin'  # Default to admin for superusers
        )

        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)

        return user


# User account model
class UserAccount(AbstractBaseUser, PermissionsMixin):
    class UserTypes(models.TextChoices):
        ADMIN = 'admin', 'Admin'
        SALES = 'sales', 'Sales'
        ACCOUNTS = 'accounts', 'Accounts'
        HYBRID = 'hybrid', 'Hybrid'

    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    user_type = models.CharField(
        max_length=20,
        choices=UserTypes.choices,
        default=UserTypes.SALES
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    added_on = models.DateTimeField(auto_now_add=True)

    objects = UserAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone', 'user_type']

    def __str__(self):
        return self.email

    def clean(self):
        if self.user_type not in [choice[0] for choice in self.UserTypes.choices]:
            raise ValidationError('Invalid user type')


# OTP model
class OTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return timezone.now() < self.created_at + timedelta(minutes=10)  # OTP valid for 10 minutes


class Farmer(models.Model):
    id = models.AutoField(primary_key=True)
    alias = models.CharField(max_length=255, null=True, unique=True)
    farmer_number = models.CharField(max_length=255, unique=True, null=True)
    name = models.CharField(max_length=255, null=True,)
    phone = models.CharField(max_length=255, unique=True, null=True)
    secondary_phone = models.CharField(max_length=255, unique=True, default=0, null=True,)
    refferal = models.CharField(max_length=255, null=True)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def save(self, *args, **kwargs):
        # Normalize alias and farmer_number to lowercase
        if self.alias:
            self.alias = self.alias.lower()
        if self.farmer_number:
            self.farmer_number = self.farmer_number.lower()
        super().save(*args, **kwargs)

    def validate_unique(self, exclude=None):
        super().validate_unique(exclude)
        # Case-insensitive validation for alias
        if Farmer.objects.filter(alias__iexact=self.alias).exclude(pk=self.pk).exists():
            raise ValidationError({"alias": "A farmer with this alias already exists."})
        # Case-insensitive validation for farmer_number
        if Farmer.objects.filter(farmer_number__iexact=self.farmer_number).exclude(pk=self.pk).exists():
            raise ValidationError({"farmer_number": "A farmer with this number already exists."})


# Machine model
class Machine(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


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