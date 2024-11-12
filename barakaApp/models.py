from datetime import timedelta

from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
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


# Farmer model
class Farmer(models.Model):
    id = models.AutoField(primary_key=True)
    alias = models.CharField(max_length=255, null=True)
    farmer_number = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()


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
    farmer_name = models.CharField(max_length=255)
    machine_id = models.ForeignKey(Machine, on_delete=models.CASCADE)
    kgs = models.CharField(max_length=255)
    output = models.CharField(max_length=255)
    price = models.CharField(max_length=255)
    amount = models.CharField(max_length=255)
    refferal = models.CharField(max_length=255, null=True)
    mill_date = models.DateField()
    added_on = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

