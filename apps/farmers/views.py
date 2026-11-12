from datetime import datetime

from django.db import IntegrityError
from django.db.models import Q, Sum, F, DecimalField, Subquery, OuterRef, ExpressionWrapper, Value
from django.db.models.functions import Coalesce, ExtractYear, ExtractMonth
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status, generics
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from apps.core.permissions import IsAdminRole
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from apps.farmers.models import Farmer
from apps.farmers.serializers import FarmerSerializer
from apps.milling.models import Milled
from apps.milling.serializers import MilledSerializer
from apps.payments.models import Payments
from apps.payments.serializers import PaymentsSerializer


# Farmer viewset
class FarmerViewSet(viewsets.ViewSet):
    permission_classes_by_action = {'create': [IsAuthenticated], 'list': [IsAuthenticated], 'update': [IsAuthenticated], 'destroy': [IsAdminRole], 'default': [IsAuthenticated]}

    def get_permissions(self):
        return [permission() for permission in
                self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    pagination_class = PageNumberPagination()

    def list(self, request):
        search = request.query_params.get("search")

        farmers = Farmer.objects.all()

        if search:
            farmers = farmers.filter(
                Q(name__icontains=search) |
                Q(alias__icontains=search)
            )

        serializer = FarmerSerializer(farmers, many=True, context={"request": request})

        response_dict = {
            "error": False,
            "message": "All Farmers List Data",
            "count": farmers.count(),
            "data": serializer.data
        }
        return Response(response_dict)

    def create(self, request):
        try:
            data = request.data.copy()

            if not data.get("refferal"):
                data["refferal"] = None

            serializer = FarmerSerializer(
                data=data,
                context={"request": request}
            )

            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(
                {
                    "error": False,
                    "message": "Farmers Data Saved Successfully",
                    "data": serializer.data
                },
                status=status.HTTP_201_CREATED
            )

        except IntegrityError as e:
            return Response(
                {
                    "error": True,
                    "message": f"Duplicate / invalid database constraint: {str(e)}"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            return Response(
                {
                    "error": True,
                    "message": f"Error During Saving Farmers Data: {str(e)}"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def retrieve(self, request, pk=None):
        queryset = Farmer.objects.all()
        farmer = get_object_or_404(queryset, pk=pk)
        serializer = FarmerSerializer(farmer,  context={"request": request})

        serializer_data = serializer.data
        # Accessing All the Milling Details of Current Farmer
        milling_details = Milled.objects.filter(farmer_id=serializer_data["id"]).order_by('-id')
        milling_details_serializers = MilledSerializer(milling_details, many=True)
        serializer_data["milling"] = milling_details_serializers.data

        # Accessing All the Payment Details of Current Farmer
        payments_details = Payments.objects.filter(farmer_id=serializer_data["id"]).order_by('-id')
        payments_details_serializers = PaymentsSerializer(payments_details, many=True)
        serializer_data["payments"] = payments_details_serializers.data

        # Access Millings per year
        millings_by_year = Milled.objects.filter(farmer_id=serializer_data["id"]).annotate(
            year=ExtractYear('added_on')).values('year').annotate(total_kilos=Sum('kgs')).order_by('year')

        # Access monthly Farmers kilos
        millings_by_month = Milled.objects.filter(farmer_id=serializer_data["id"]).annotate(
            year=ExtractYear('added_on'),
            month=ExtractMonth('added_on')
        ).values('year', 'month').annotate(total_kilos=Sum('kgs')).order_by('year', 'month')

        # Accessing all kgs of current farmer
        kgs_total = Milled.objects.filter(farmer_id=serializer_data["id"])
        kgs = 0
        output = 0
        amount = 0
        for total in kgs_total:
            kgs += float(total.kgs)
            output += float(total.output)
            amount += float(total.amount)

        # Accessing total payments of current farmer
        total_payment = Payments.objects.filter(farmer_id= serializer_data["id"])
        payment = 0
        for total_payed in total_payment:
            payment += float(total_payed.payment)

        balance = amount - payment
        return Response({
            "error": False,
            "message": "Single Data Fetch",
            "kgs": kgs,
            "millings_by_year": list(millings_by_year),
            "millings_by_month": list(millings_by_month),
            "output": output,
            "payed_total": payment,
            "balance": balance,
            "data": serializer_data
        })

    def update(self, request, pk=None):
        try:
            queryset = Farmer.objects.all()
            farmer = get_object_or_404(queryset, pk=pk)
            serializer = FarmerSerializer(farmer, data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Successfully Updated Farmer Data"}
        except:
            dict_response = {"error": True, "message": "Error During Updating Farmer Data"}

        return Response(dict_response)

    def destroy(self, request, pk=None):
        queryset = Farmer.objects.all()
        farmer = get_object_or_404(queryset, pk=pk)
        farmer.delete()
        return Response({"error": False, "message": "Farmer Deleted"})

    @action(detail=False, methods=['get'], url_path='farmers-with-balance')
    def farmers_with_balance(self, request):
        # Calculate the balance for each farmer with a positive balance
        farmers_with_balance = Farmer.objects.annotate(
            total_milled=Subquery(
                Milled.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(total=Sum(F('amount'), output_field=DecimalField(max_digits=10, decimal_places=2)))
                .values('total')
            ),
            total_payments=Subquery(
                Payments.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(total=Sum('payment', output_field=DecimalField(max_digits=10, decimal_places=2))
                          )
                .values('total')
            )
        ).annotate(
            balance=F('total_milled') - F('total_payments')
        ).filter(balance__gt=0).order_by('id')

        # Serialize the data
        serializer = FarmerSerializer(farmers_with_balance, many=True, context={"request": request})

        # Append the balance to each farmer's data in the serialized response
        data_with_balance = serializer.data
        for farmer_data, balance in zip(data_with_balance, farmers_with_balance.values_list('balance', flat=True)):
            farmer_data['balance'] = balance
        response_dict = {"error": False, "message": "Farmers with Balance > 0", "data": data_with_balance}

        return Response(response_dict)

    @action(detail=False, methods=['get'], url_path='farmers-with-excess')
    def farmers_with_excess(self, request):
        # Calculate the balance for each farmer with an excess balance
        farmers_with_excess = Farmer.objects.annotate(
            total_milled=Subquery(
                Milled.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(total=Sum(F('amount'), output_field=DecimalField(max_digits=10, decimal_places=2)))
                .values('total')
            ),
            total_payments=Subquery(
                Payments.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(total=Sum('payment', output_field=DecimalField(max_digits=10, decimal_places=2))
                          )
                .values('total')
            )
        ).annotate(
            balance=F('total_milled') - F('total_payments')
        ).filter(balance__lt=0).order_by('id')

        # Serialize the data
        serializer = FarmerSerializer(farmers_with_excess, many=True, context={"request": request})

        # Append the balance to each farmer's data in the serialized response
        data_with_balance = serializer.data
        for farmer_data, balance in zip(data_with_balance, farmers_with_excess.values_list('balance', flat=True)):
            farmer_data['balance'] = balance
        response_dict = {"error": False, "message": "Farmers with Balance < 0", "data": data_with_balance}

        return Response(response_dict)

    @action(detail=False, methods=['get'], url_path='total-balance')
    def total_balance(self, request):
        total_milled_subquery = Subquery(
            Milled.objects.filter(farmer_id=OuterRef('id'))
            .values('farmer_id')
            .annotate(
                total=Sum('amount', output_field=DecimalField(max_digits=10, decimal_places=2))
            )
            .values('total'),
            output_field=DecimalField(max_digits=10, decimal_places=2)
        )

        total_payments_subquery = Subquery(
            Payments.objects.filter(farmer_id=OuterRef('id'))
            .values('farmer_id')
            .annotate(
                total=Sum('payment', output_field=DecimalField(max_digits=10, decimal_places=2))
            )
            .values('total'),
            output_field=DecimalField(max_digits=10, decimal_places=2)
        )

        farmers_with_balance = Farmer.objects.annotate(
            total_milled=Coalesce(total_milled_subquery, Value(0),
                                  output_field=DecimalField(max_digits=10, decimal_places=2)),
            total_payments=Coalesce(total_payments_subquery, Value(0),
                                    output_field=DecimalField(max_digits=10, decimal_places=2)),
        ).annotate(
            balance=ExpressionWrapper(
                F('total_milled') - F('total_payments'),
                output_field=DecimalField(max_digits=10, decimal_places=2)
            )
        )

        total_balance = farmers_with_balance.aggregate(
            total_balance=Coalesce(Sum('balance'), Value(0), output_field=DecimalField(max_digits=10, decimal_places=2))
        )['total_balance']

        return Response({"total_balance": float(total_balance)})


# Farmer only viewset
class FarmerOnlyViewSet(generics.ListAPIView):
    serializer_class = FarmerSerializer

    def get_queryset(self):
        return Farmer.objects.all()


# Farmer name viewset
class FarmerNameViewSet(generics.ListAPIView):
    serializer_class = FarmerSerializer

    def get_queryset(self):
        name = self.request.query_params.get("name")  # Access query parameters
        if name:
            return Farmer.objects.filter(name__icontains=name)
        return Farmer.objects.all()


# Positive Balance
class TotalPositiveBalanceView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Calculate the total positive balance
        total_balance = Farmer.objects.annotate(
            total_milled=Subquery(
                Milled.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(
                    total=Sum(F('amount'), output_field=DecimalField(max_digits=10, decimal_places=2)))
                .values('total')
            ),
            total_payments=Subquery(
                Payments.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(total=Sum('payment', output_field=DecimalField(max_digits=10, decimal_places=2)))
                .values('total')
            )
        ).annotate(
            balance=F('total_milled') - F('total_payments')
        ).filter(balance__gt=0).aggregate(total_positive_balance=Sum('balance'))

        # Rest of the code for additional data can be added here
        # Example: Calculate profit, count orders, and other statistics

        # Serialize the data and create a response dictionary
        response_data = {
            "total_positive_balance": total_balance['total_positive_balance'],
            # Add more data here as needed
        }

        return Response(response_data, status=status.HTTP_200_OK)


# Negative Balance
class TotalNegativeBalanceView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Calculate the total positive balance
        total_balance = Farmer.objects.annotate(
            total_milled=Subquery(
                Milled.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(
                    total=Sum(F('amount'), output_field=DecimalField(max_digits=10, decimal_places=2)))
                .values('total')
            ),
            total_payments=Subquery(
                Payments.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(total=Sum('payment', output_field=DecimalField(max_digits=10, decimal_places=2)))
                .values('total')
            )
        ).annotate(
            balance=F('total_milled') - F('total_payments')
        ).filter(balance__lt=0).aggregate(total_negative_balance=Sum('balance'))

        return Response({"total_negative_balance": total_balance['total_negative_balance']}, status=status.HTTP_200_OK)


# Farmers with Positive Balance
class FarmersWithPositiveBalanceViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        # Optional period filter (YYYY-MM-DD). When given, only debt from
        # millings whose mill_date falls in the period counts: the amount
        # milled in the period minus the payments made against those millings.
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        try:
            if start_date:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            if end_date:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            return Response(
                {"error": True, "message": "Dates must be in YYYY-MM-DD format.", "data": []},
                status=status.HTTP_400_BAD_REQUEST,
            )

        milled_filter = Q(farmer_id=OuterRef('id'))
        payments_filter = Q(farmer_id=OuterRef('id'))
        if start_date:
            milled_filter &= Q(mill_date__gte=start_date)
            payments_filter &= Q(milling_id__mill_date__gte=start_date)
        if end_date:
            milled_filter &= Q(mill_date__lte=end_date)
            payments_filter &= Q(milling_id__mill_date__lte=end_date)

        total_milled_subquery = Milled.objects.filter(
            milled_filter
        ).values('farmer_id').annotate(
            total=Sum('amount')
        ).values('total')[:1]

        total_payments_subquery = Payments.objects.filter(
            payments_filter
        ).values('farmer_id').annotate(
            total=Sum('payment')
        ).values('total')[:1]

        farmers_with_balance = Farmer.objects.annotate(
            total_milled=Coalesce(
                Subquery(total_milled_subquery, output_field=DecimalField(max_digits=10, decimal_places=2)),
                Value(0),
                output_field=DecimalField(max_digits=10, decimal_places=2)
            ),
            total_payments=Coalesce(
                Subquery(total_payments_subquery, output_field=DecimalField(max_digits=10, decimal_places=2)),
                Value(0),
                output_field=DecimalField(max_digits=10, decimal_places=2)
            )
        ).annotate(
            balance=ExpressionWrapper(
                F('total_milled') - F('total_payments'),
                output_field=DecimalField(max_digits=10, decimal_places=2)
            )
        ).filter(balance__gt=0).order_by('id')

        serializer = FarmerSerializer(farmers_with_balance, many=True, context={"request": request})
        data_with_balance = serializer.data

        for farmer_data, balance in zip(data_with_balance, farmers_with_balance.values_list('balance', flat=True)):
            farmer_data['balance'] = float(balance)

        return Response({
            "error": False,
            "message": "All Debtors List Data",
            "data": data_with_balance
        })


# Farmers with Negative Balance
class FarmersWithNegativeBalanceViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        # Calculate the balance for each farmer
        farmers_with_balance = Farmer.objects.annotate(
            total_milled=Subquery(
                Milled.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(
                    total=Sum(F('amount'), output_field=DecimalField(max_digits=10, decimal_places=2)))
                .values('total')
            ),
            total_payments=Subquery(
                Payments.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(total=Sum('payment', output_field=DecimalField(max_digits=10, decimal_places=2)))
                .values('total')
            )
        ).annotate(
            balance=F('total_milled') - F('total_payments')
        ).filter(balance__lt=0).order_by('id')

        # Serialize the data
        serializer = FarmerSerializer(farmers_with_balance, many=True, context={"request": request})

        # Append the balance to each farmer's data in the serialized response
        data_with_balance = serializer.data
        for farmer_data, balance in zip(data_with_balance, farmers_with_balance.values_list('balance', flat=True)):
            farmer_data['balance'] = balance
        response_dict = {"error": False, "message": "Overpayment List Data", "data": data_with_balance}

        return Response(response_dict)
