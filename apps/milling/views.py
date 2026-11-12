from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from apps.core.permissions import IsAdminRole
from rest_framework.response import Response

from apps.core.pagination import FiftyPerPagePagination
from apps.milling.models import Milled
from apps.milling.serializers import MilledSerializer


# Milled viewset
class MilledViewSet(viewsets.ViewSet):
    pagination_class = FiftyPerPagePagination  # add this

    permission_classes_by_action = {
        'create': [IsAuthenticated],
        'list': [IsAuthenticated],
        'update': [IsAdminRole],
        'destroy': [IsAdminRole],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in
                self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    # List with pagination
    def list(self, request):
        paginator = self.pagination_class()

        queryset = Milled.objects.all().order_by('-id')

        # SEARCH (before pagination)
        search = request.query_params.get('search', None)

        if search:
            queryset = queryset.filter(
                Q(farmer_id__alias__icontains=search) |
                Q(machine_id__name__icontains=search) |
                Q(kgs__icontains=search) |
                Q(amount__icontains=search)
            )

        # PAGINATE filtered queryset
        page = paginator.paginate_queryset(queryset, request, view=self)

        if page is not None:
            serializer = MilledSerializer(page, many=True, context={"request": request})
            return paginator.get_paginated_response({
                "error": False,
                "message": "Milling List",
                "data": serializer.data
            })

        # fallback
        serializer = MilledSerializer(queryset, many=True, context={"request": request})
        return Response({
            "error": False,
            "message": "Milling List",
            "data": serializer.data
        })

    # Create a new milled instance
    def create(self, request):
        serializer = MilledSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Retrieve a milling
    def retrieve(self, request, pk=None):
        try:
            milled = get_object_or_404(Milled, pk=pk)
            serializer = MilledSerializer(milled)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Milled.DoesNotExist:
            return Response({'error': 'Milled instance not found'}, status=status.HTTP_404_NOT_FOUND)

    # Update a milling instance
    def update(self, request, pk=None):
        try:
            milled = get_object_or_404(Milled, pk=pk)
            serializer = MilledSerializer(milled, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Milled instance updated successfully", "data": serializer.data},
                                status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Milled.DoesNotExist:
            return Response({"error": True, "message": "Milled instance not found"}, status=status.HTTP_404_NOT_FOUND)

    # Delete a milling instance
    def destroy(self, request, pk=None):
        milled = get_object_or_404(Milled, pk=pk)
        milled.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
