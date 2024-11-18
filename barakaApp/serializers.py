from rest_framework import serializers
from django.contrib.auth import get_user_model

from barakaApp.models import Farmer, Milled, Machine

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


# Farmer serializer
class FarmerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Farmer
        fields = "__all__"


# Machines Serializer
class MachineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Machine
        fields = "__all__"


# Milled serializer
class MilledSerializer(serializers.ModelSerializer):
    class Meta:
        model = Milled
        fields = "__all__"

    def to_representation(self, instance):
        response = super().to_representation(instance)
        response["farmer"] = FarmerSerializer(instance.farmer_id).data
        response["machine"] = MachineSerializer(instance.machine_id).data
        return response