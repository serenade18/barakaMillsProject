from rest_framework import serializers

from apps.farmers.models import Farmer


# Farmer serializer
class FarmerSerializer(serializers.ModelSerializer):
    refferal = serializers.CharField(required=False, allow_null=True, allow_blank=True)

    class Meta:
        model = Farmer
        fields = "__all__"
