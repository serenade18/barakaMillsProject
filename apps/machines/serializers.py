from rest_framework import serializers

from apps.machines.models import Machine


# Machines Serializer
class MachineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Machine
        fields = "__all__"
