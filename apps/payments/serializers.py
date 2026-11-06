from rest_framework import serializers

from apps.farmers.serializers import FarmerSerializer
from apps.milling.serializers import MilledSerializer
from apps.payments.models import Payments


# Payment serializer
class PaymentsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payments
        fields = "__all__"

    def to_representation(self, instance):
        response = super().to_representation(instance)
        response["milling"] = MilledSerializer(instance.milling_id).data
        response["farmer"] = FarmerSerializer(instance.farmer_id).data
        return response
