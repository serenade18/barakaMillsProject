from datetime import timedelta

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
from django.core.exceptions import ValidationError

from apps.core import APP_LABEL


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
    # Holds a Role.name. No `choices`: admins can add custom roles, so the
    # Role table (not UserTypes) is the list of valid values.
    user_type = models.CharField(
        max_length=20,
        default=UserTypes.SALES
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    added_on = models.DateTimeField(auto_now_add=True)

    objects = UserAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone', 'user_type']

    class Meta:
        app_label = APP_LABEL

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        # Only admins may sign in to Django admin or hold superuser rights;
        # every other role (hybrid included) is always plain staff.
        if self.user_type != self.UserTypes.ADMIN:
            self.is_staff = False
            self.is_superuser = False
        super().save(*args, **kwargs)

    def clean(self):
        if not Role.objects.filter(name=self.user_type).exists():
            raise ValidationError('Invalid user type')


# Staff roles. A user's role is UserAccount.user_type == Role.name.
# The built-in roles (admin, sales, accounts, hybrid) are system roles: the
# code relies on their names (admin has full access), so they cannot be
# renamed or deleted. Custom roles get the same access as non-admin staff.
class Role(models.Model):
    SYSTEM_ROLES = ['admin', 'sales', 'accounts', 'hybrid']

    name = models.CharField(max_length=20, unique=True)
    description = models.TextField(blank=True, default='')
    is_system = models.BooleanField(default=False)
    added_on = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = APP_LABEL
        ordering = ['id']

    def __str__(self):
        return self.name


# OTP model
class OTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = APP_LABEL

    def is_valid(self):
        return timezone.now() < self.created_at + timedelta(minutes=10)  # OTP valid for 10 minutes
