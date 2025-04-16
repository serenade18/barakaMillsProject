import random
from datetime import timedelta, date

from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import viewsets, status, generics, permissions

from django.db.models import Q, Sum, F, DecimalField, Subquery, OuterRef, FloatField
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from barakaApp.models import UserAccount, OTP, Farmer, Machine, Milled, Payments
from barakaApp.serializers import UserAccountSerializer, UserCreateSerializer, FarmerSerializer, MachineSerializer, \
    MilledSerializer, PaymentsSerializer

User = get_user_model()

# Create your views here.


class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserAccountSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# Admin viewset
class AdminUserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [AllowAny],
        'verify_otp': [AllowAny],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Hash the password before saving the user
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

            # Set admin user attributes
            serializer.validated_data.update({
                'is_superuser': True,
                'is_active': True,
                'is_staff': True,
                'user_type': 'admin'
            })

            serializer.save()

            return Response(
                {'message': 'Admin account created successfully'},
                status=status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Hybrid viewset
class HybridUserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {'create': [AllowAny], 'list': [IsAdminUser], 'verify_otp': [AllowAny], 'default': [IsAuthenticated]}

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        try:
            users = UserAccount.objects.all()
            serializer = UserAccountSerializer(users, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Users List Data", "data": response_data}

        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(response_dict,
                        status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK)

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Hash the password before saving the user
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

            # Generate OTP
            otp = random.randint(100000, 999999)
            email = serializer.validated_data['email']

            # Send OTP to email
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}',
                'from@example.com',
                [email],
                fail_silently=False,
            )

            # Save OTP to the database
            OTP.objects.create(email=email, otp=otp)

            # Set the user as inactive
            serializer.validated_data['is_active'] = False
            serializer.save()

            # Save OTP and email in session
            request.session['otp'] = otp
            request.session['email'] = email

            return Response({'message': 'OTP sent to email'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def verify_otp(self, request):
        otp = request.data.get('otp')

        if not otp:
            return Response({'error': 'Missing OTP'}, status=status.HTTP_400_BAD_REQUEST)

        email = request.session.get('email')
        session_otp = request.session.get('otp')

        if otp != str(session_otp):
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            otp_record = OTP.objects.get(email=email, otp=otp)
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if not otp_record.is_valid():
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        # Activate the user
        try:
            user = UserAccount.objects.get(email=email)
            user.is_active = True
            user.is_staff = True
            user.is_superuser = False
            user.user_type = 'hybrid'
            user.save()
        except UserAccount.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Clear session data and delete OTP
        del request.session['otp']
        del request.session['email']
        otp_record.delete()

        return Response({'message': 'User activated successfully'}, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Sales viewset
class SalesUserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {'create': [AllowAny], 'list': [IsAdminUser], 'verify_otp': [AllowAny], 'default': [IsAuthenticated]}

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        try:
            users = UserAccount.objects.all()
            serializer = UserAccountSerializer(users, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Users List Data", "data": response_data}

        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(response_dict,
                        status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK)

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Hash the password before saving the user
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

            # Generate OTP
            otp = random.randint(100000, 999999)
            email = serializer.validated_data['email']

            # Send OTP to email
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}',
                'from@example.com',
                [email],
                fail_silently=False,
            )

            # Save OTP to the database
            OTP.objects.create(email=email, otp=otp)

            # Set the user as inactive
            serializer.validated_data['is_active'] = False
            serializer.save()

            # Save OTP and email in session
            request.session['otp'] = otp
            request.session['email'] = email

            return Response({'message': 'OTP sent to email'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def verify_otp(self, request):
        otp = request.data.get('otp')

        if not otp:
            return Response({'error': 'Missing OTP'}, status=status.HTTP_400_BAD_REQUEST)

        email = request.session.get('email')
        session_otp = request.session.get('otp')

        if otp != str(session_otp):
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            otp_record = OTP.objects.get(email=email, otp=otp)
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if not otp_record.is_valid():
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        # Activate the user
        try:
            user = UserAccount.objects.get(email=email)
            user.is_active = True
            user.user_type = 'sales'
            user.save()
        except UserAccount.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Clear session data and delete OTP
        del request.session['otp']
        del request.session['email']
        otp_record.delete()

        return Response({'message': 'User activated successfully'}, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Accounts viewset
class AccountsUserViewSet(viewsets.ViewSet):
    permission_classes_by_action = {'create': [AllowAny], 'list': [IsAdminUser], 'verify_otp': [AllowAny], 'default': [IsAuthenticated]}

    def get_permissions(self):
        return [permission() for permission in self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        try:
            users = UserAccount.objects.all()
            serializer = UserAccountSerializer(users, many=True, context={"request": request})
            response_data = serializer.data
            response_dict = {"error": False, "message": "All Users List Data", "data": response_data}

        except ValidationError as e:
            response_dict = {"error": True, "message": "Validation Error", "details": str(e)}
        except Exception as e:
            response_dict = {"error": True, "message": "An Error Occurred", "details": str(e)}

        return Response(response_dict,
                        status=status.HTTP_400_BAD_REQUEST if response_dict['error'] else status.HTTP_200_OK)

    def create(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Hash the password before saving the user
            password = make_password(serializer.validated_data['password'])
            serializer.validated_data['password'] = password

            # Generate OTP
            otp = random.randint(100000, 999999)
            email = serializer.validated_data['email']

            # Send OTP to email
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}',
                'from@example.com',
                [email],
                fail_silently=False,
            )

            # Save OTP to the database
            OTP.objects.create(email=email, otp=otp)

            # Set the user as inactive
            serializer.validated_data['is_active'] = False
            serializer.save()

            # Save OTP and email in session
            request.session['otp'] = otp
            request.session['email'] = email

            return Response({'message': 'OTP sent to email'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def verify_otp(self, request):
        otp = request.data.get('otp')

        if not otp:
            return Response({'error': 'Missing OTP'}, status=status.HTTP_400_BAD_REQUEST)

        email = request.session.get('email')
        session_otp = request.session.get('otp')

        if otp != str(session_otp):
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            otp_record = OTP.objects.get(email=email, otp=otp)
        except OTP.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        if not otp_record.is_valid():
            return Response({'error': 'OTP expired'}, status=status.HTTP_400_BAD_REQUEST)

        # Activate the user
        try:
            user = UserAccount.objects.get(email=email)
            user.is_active = True
            user.user_type = 'accounts'
            user.save()
        except UserAccount.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Clear session data and delete OTP
        del request.session['otp']
        del request.session['email']
        otp_record.delete()

        return Response({'message': 'User activated successfully'}, status=status.HTTP_201_CREATED)

    def retrieve(self, request, pk=None):
        queryset = UserAccount.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = UserAccountSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        serializer = UserAccountSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        user = UserAccount.objects.get(pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Farmer viewset
class FarmerViewSet(viewsets.ViewSet):
    permission_classes_by_action = {'create': [IsAuthenticated], 'list': [IsAuthenticated], 'update': [IsAuthenticated], 'destroy': [IsAdminUser], 'default': [IsAuthenticated]}

    def get_permissions(self):
        return [permission() for permission in
                self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    pagination_class = PageNumberPagination()

    def list(self, request):
        farmers = Farmer.objects.all()
        serializer = FarmerSerializer(farmers, many=True, context={"request": request})
        response_data = serializer.data
        response_dict = {"error": False, "message": "All Farmers List Data", "data": response_data}
        return Response(response_dict)

    def create(self, request):
        try:
            # Ensure referral is optional
            data = request.data.copy()
            if "refferal" not in data or not data["refferal"]:
                data["refferal"] = None  # Handle missing or empty referral field

            serializer = FarmerSerializer(data=data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Farmers Data Saved Successfully"}
        except Exception as e:
            dict_response = {"error": True, "message": f"Error During Saving Farmers Data: {str(e)}"}

        return Response(dict_response)

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
        farmers_with_balance = Farmer.objects.annotate(
            total_milled=Subquery(
                Milled.objects.filter(farmer_id=OuterRef('id'))
                .values('farmer_id')
                .annotate(
                    total=Sum(F('amount'), output_field=DecimalField(max_digits=10, decimal_places=2))
                )
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
        ).order_by('id')  # Remove filtering for balance > 0

        total_balance = farmers_with_balance.aggregate(total_balance=Sum('balance'))['total_balance'] or 0

        return Response({"total_balance": total_balance})


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


# Milled viewset
class MilledViewSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'create': [IsAuthenticated],
        'list': [IsAuthenticated],
        'update': [IsAdminUser],
        'destroy': [IsAdminUser],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in
                self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    # List all milled
    def list(self, request):
        milling = Milled.objects.all().order_by('-id')
        serializer = MilledSerializer(milling, many=True, context={"request": request})
        response_data = serializer.data
        response_dict = {"error": False, "message": "All Milling List Data", "data": response_data}
        return Response(response_dict)

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


# Dashboard viewset
class DashboardViewsSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'list': [IsAdminUser],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in
                self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    # List total farmers in the system
    def list(self, request):
        # Get total farmers
        farmer = Farmer.objects.all()
        farmer_serializer = FarmerSerializer(farmer, many=True, context={"request": request})

        # Get total milled kilos and amount
        milled = Milled.objects.all()
        kgs = 0
        amount = 0
        milling_revenue = 0
        for total in milled:
            kgs += float(total.kgs)
            amount += float(total.amount)
            milling_revenue += float(total.price) * float(total.kgs)

        # Get total payments
        payed = Payments.objects.all()
        payment = 0
        for full_payment in payed:
            payment += float(full_payment.payment)

        # Get total balance
        balance = amount - payment

        dict_response = {
            "error": False,
            "message": "Home page data",
            "farmer": len(farmer_serializer.data),
            "total_milled": kgs,
            "total_amount": amount,
            "total_payment": payment,
            "total_balance": balance,
            "milling_revenue": milling_revenue
        }
        return Response(dict_response)


# Payment viewset
class PaymentViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination()

    def list(self, request):
        paginator = self.pagination_class
        search_query = request.query_params.get('search', None)
        payments_query = Payments.objects.all().order_by('-id')

        # Implementing the search functionality:
        if search_query is not None:
            if search_query.isdigit():
                # Search by orders_id if the search query is a number
                payments_query = payments_query.filter(
                    Q(orders_id__id=search_query)
                )
            else:
                # Search by other fields for non-numeric queries
                payments_query = payments_query.filter(
                    Q(paying_number__icontains=search_query)
                )

        page = paginator.paginate_queryset(payments_query, request, view=self)
        if page is not None:
            serializer = PaymentsSerializer(page, many=True, context={"request": request})
            response_data = paginator.get_paginated_response(serializer.data).data
        else:
            serializer = PaymentsSerializer(payments_query, many=True, context={"request": request})
            response_data = serializer.data

        response_dict = {
            "error": False,
            "message": "All Payments List Data",
            "data": response_data
        }
        return Response(response_dict)

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


# yearly chart
class YearlyDataViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        year_dates = Milled.objects.order_by().values("mill_date__year").distinct()
        year_kilos_chart_list = []
        for year in year_dates:
            access_year = year["mill_date__year"]

            year_data = Milled.objects.filter(mill_date__year=access_year)
            year_kilos = 0
            access_year_date = date(year=access_year, month=1, day=1)
            for year_single in year_data:
                year_kilos += float(year_single.kgs)

            year_kilos_chart_list.append({"date": access_year_date, "amt": year_kilos})

        dict_response = {
            "error": False,
            "message": "Yearly Data",
            "year_kilos": year_kilos_chart_list
        }

        return Response(dict_response)


# Monthly chart
class MonthlyDataViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        month_dates = Milled.objects.order_by().values("mill_date__month", "mill_date__year").distinct()
        month_kilos_chart_list = []
        for month in month_dates:
            access_month = month["mill_date__month"]
            access_year = month["mill_date__year"]

            month_data = Milled.objects.filter(mill_date__month=access_month, mill_date__year=access_year)
            month_kilos = 0
            access_date = date(year=access_year, month=access_month, day=1)
            for month_single in month_data:
                month_kilos += float(month_single.kgs)

            month_kilos_chart_list.append({"date": access_date, "amt": month_kilos})

        dict_response = {
            "error": False,
            "message": "Monthly Data",
            "month_kilos_chart": month_kilos_chart_list,
        }

        return Response(dict_response)


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
        ).filter(balance__gt=0).order_by('id')

        # Serialize the data
        serializer = FarmerSerializer(farmers_with_balance, many=True, context={"request": request})

        # Append the balance to each farmer's data in the serialized response
        data_with_balance = serializer.data
        for farmer_data, balance in zip(data_with_balance, farmers_with_balance.values_list('balance', flat=True)):
            farmer_data['balance'] = balance
        response_dict = {"error": False, "message": "All Debtors List Data", "data": data_with_balance}

        return Response(response_dict)


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

