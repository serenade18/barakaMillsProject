from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication

from apps.core.pagination import FiftyPerPagePagination
from apps.payments.models import Payments
from apps.payments.serializers import PaymentsSerializer


# Payment viewset
class PaymentViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = FiftyPerPagePagination  # FIXED

    def list(self, request):
        paginator = self.pagination_class()
        search_query = request.query_params.get('search', None)
        payment_mode = request.query_params.get('payment_mode', None)

        payments_query = Payments.objects.all().order_by('-id')

        # Filter by search (receipt, farmer, milling id, etc.)
        if search_query:
            if search_query.isdigit():
                payments_query = payments_query.filter(
                    Q(milling_id=search_query) |
                    Q(receipt_number__icontains=search_query)
                )
            else:
                payments_query = payments_query.filter(
                    Q(receipt_number__icontains=search_query) |
                    Q(farmer_id__alias__icontains=search_query)
                )

        # Filter by payment mode if provided
        if payment_mode:
            try:
                payment_mode_int = int(payment_mode)
                payments_query = payments_query.filter(payment_mode=payment_mode_int)
            except ValueError:
                pass  # ignore invalid payment_mode values

        page = paginator.paginate_queryset(payments_query, request, view=self)
        if page is not None:
            serializer = PaymentsSerializer(page, many=True, context={"request": request})
            return paginator.get_paginated_response({
                "error": False,
                "message": "All Payments List Data",
                "data": serializer.data
            })

        serializer = PaymentsSerializer(payments_query, many=True, context={"request": request})
        return Response({
            "error": False,
            "message": "All Payments List Data",
            "data": serializer.data
        })

    # Create a new payment instance
    def create(self, request):
        serializer = PaymentsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Retrieve a payment
    def retrieve(self, request, pk=None):
        try:
            payment = get_object_or_404(Payments, pk=pk)
            serializer = PaymentsSerializer(payment)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Payments.DoesNotExist:
            return Response({'error': 'Payment instance not found'}, status=status.HTTP_404_NOT_FOUND)

    # Update a milling instance
    def update(self, request, pk=None):
        try:
            payment = get_object_or_404(Payments, pk=pk)
            serializer = PaymentsSerializer(payment, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({"message": "Payments instance updated successfully", "data": serializer.data},
                                status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Payments.DoesNotExist:
            return Response({"error": True, "message": "Payments instance not found"}, status=status.HTTP_404_NOT_FOUND)

    # Delete a milling instance
    def destroy(self, request, pk=None):
        payment = get_object_or_404(Payments, pk=pk)
        payment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
