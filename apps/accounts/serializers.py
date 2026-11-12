from rest_framework import serializers
from django.contrib.auth import get_user_model

from apps.accounts.models import Role

User = get_user_model()


# User create serializer
class UserCreateSerializer(serializers.ModelSerializer):
    user_type = serializers.CharField(default='sales', required=False)

    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'phone', 'user_type', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        user_type = attrs.get('user_type', 'sales')
        if user_type not in ['admin', 'sales', 'accounts', 'hybrid']:
            raise serializers.ValidationError("Invalid user type")

        return attrs


# User serializer with login time
class CustomUserSerializer(serializers.ModelSerializer):
    last_login = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'phone', 'user_type', 'last_login']


# User serializer with no login time
class UserAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'phone', 'user_type',  'added_on']


# Role serializer
class RoleSerializer(serializers.ModelSerializer):
    user_count = serializers.SerializerMethodField()

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'is_system', 'user_count', 'added_on']
        read_only_fields = ['is_system', 'user_count', 'added_on']

    def get_user_count(self, obj):
        return User.objects.filter(user_type=obj.name).count()

    def validate_name(self, value):
        # Stored lowercase, like user_type; spaces become underscores.
        name = '_'.join(value.strip().lower().split())
        if not name:
            raise serializers.ValidationError('Name is required.')
        if len(name) > 20:
            raise serializers.ValidationError('Name must be 20 characters or fewer.')
        qs = Role.objects.filter(name=name)
        if self.instance:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError('A role with this name already exists.')
        if self.instance and self.instance.is_system and name != self.instance.name:
            raise serializers.ValidationError('Built-in roles cannot be renamed.')
        return name
