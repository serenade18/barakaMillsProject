import random
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import viewsets, status, generics, permissions
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from barakaApp.models import UserAccount, OTP, Farmer, Machine, Milled
from barakaApp.serializers import UserAccountSerializer, UserCreateSerializer, FarmerSerializer, MachineSerializer, \
    MilledSerializer

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
            serializer = FarmerSerializer(data=request.data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            dict_response = {"error": False, "message": "Farmers Data Saved Successfully"}
        except:
            dict_response = {"error": True, "message": "Error During Saving Farmers Data"}

        return Response(dict_response)

    def retrieve(self, request, pk=None):
        queryset = Farmer.objects.all()
        farmer = get_object_or_404(queryset, pk=pk)
        serializer = FarmerSerializer(farmer)
        return Response(serializer.data)

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
        milled = Milled.objects.all()
        serializer = MilledSerializer(milled, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # Create a new milled instance
    def create(self, request):
        serializer = MilledSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # Retrieve a specific delivery point
    def retrieve(self, request, pk=None):
        try:
            milled = get_object_or_404(Milled, pk=pk)
            serializer = MilledSerializer(milled)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Milled.DoesNotExist:
            return Response({'error': 'Milled instance not found'}, status=status.HTTP_404_NOT_FOUND)

    # Update a delivery point
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

    # Delete a delivery point
    def destroy(self, request, pk=None):
        milled = get_object_or_404(Milled, pk=pk)
        milled.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Dashboard viewset
class DashboardViewsSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    # List total farmers in the system
    def get(self, request):
        farmer = Farmer.objects.all()
        farmer_serializer = FarmerSerializer(farmer, many=True, context={"request": request})

        dict_response = {
            "error": False,
            "message": "Home page data",
            "farmer": len(farmer_serializer.data),
        }
        return Response(dict_response)
