from rest_framework import serializers

from apps.farmers.serializers import FarmerSerializer
from apps.machines.serializers import MachineSerializer
from apps.milling.models import Milled


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
