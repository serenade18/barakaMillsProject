from rest_framework import serializers
from django.contrib.auth import get_user_model

from barakaApp.models import Farmer

User = get_user_model()


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


class CustomUserSerializer(serializers.ModelSerializer):
    last_login = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'phone', 'user_type', 'last_login']


class UserAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'phone', 'user_type',  'added_on']


class FarmerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Farmer
        fields = "__all__"