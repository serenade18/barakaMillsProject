from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status, generics
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response

from apps.machines.models import Machine
from apps.machines.serializers import MachineSerializer


# Machine viewset
class MachineViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAdminUser],
        'list': [IsAuthenticated],
        'update': [IsAdminUser],
        'destroy': [IsAdminUser],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in
                self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    # List all machines
    def list(self, request):
        machine = Machine.objects.all()
        serializer = MachineSerializer(machine, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # Create a new machine instance
    def create(self, request):
        serializer = MachineSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Retrieve a specific machine
    def retrieve(self, request, pk=None):
        try:
            machine = get_object_or_404(Machine, pk=pk)
            serializer = MachineSerializer(machine)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Machine.DoesNotExist:
            return Response({'error': 'Machine point not found'}, status=status.HTTP_404_NOT_FOUND)

    # Update a machine
    def update(self, request, pk=None):
        try:
            machine = get_object_or_404(Machine, pk=pk)
            serializer = MachineSerializer(machine, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Machine updated successfully", "data": serializer.data},
                                status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Machine.DoesNotExist:
            return Response({"error": True, "message": "Delivery point not found"}, status=status.HTTP_404_NOT_FOUND)

    # Delete a machine
    def destroy(self, request, pk=None):
        machine = get_object_or_404(Machine, pk=pk)
        machine.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Farmer only viewset
class MachineOnlyViewSet(generics.ListAPIView):
    serializer_class = MachineSerializer

    def get_queryset(self):
        return Machine.objects.all()


# Machine name viewset
class MachineNameViewSet(generics.ListAPIView):
    serializer_class = MachineSerializer

    def get_queryset(self):
        name = self.request.query_params.get("name")  # Access query parameters
        if name:
            return Machine.objects.filter(name__icontains=name)
        return Machine.objects.all()
