import random

from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password, check_password
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from apps.core.permissions import IsAdminRole
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import UserAccount, OTP
from apps.accounts.serializers import UserAccountSerializer, UserCreateSerializer


class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserAccountSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        # Only allow safe fields — never let the user elevate their own role
        ALLOWED_FIELDS = {'name', 'phone', 'email'}
        data = {k: v for k, v in request.data.items() if k in ALLOWED_FIELDS}

        if not data:
            return Response(
                {'error': 'No valid fields provided. Allowed fields: name, phone, email'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = UserAccountSerializer(request.user, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Change password
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        current_password = request.data.get('current_password', '').strip()
        new_password = request.data.get('new_password', '').strip()
        confirm_password = request.data.get('confirm_password', '').strip()

        # ── Validation ──────────────────────────────────────────────────────
        if not all([current_password, new_password, confirm_password]):
            return Response(
                {'error': 'current_password, new_password and confirm_password are all required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not check_password(current_password, user.password):
            return Response(
                {'error': 'Current password is incorrect.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if new_password != confirm_password:
            return Response(
                {'error': 'new_password and confirm_password do not match.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if len(new_password) < 8:
            return Response(
                {'error': 'New password must be at least 8 characters long.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if current_password == new_password:
            return Response(
                {'error': 'New password must be different from the current password.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ── Save ─────────────────────────────────────────────────────────────
        user.password = make_password(new_password)
        user.save(update_fields=['password'])

        return Response(
            {'message': 'Password changed successfully.'},
            status=status.HTTP_200_OK,
        )


# Admin viewset
class AdminUserViewSet(viewsets.ViewSet):
    # Creating an admin (an active superuser) must never be open to the
    # public; only an existing admin may do it.
    permission_classes_by_action = {
        'create': [IsAdminRole],
        'verify_otp': [AllowAny],
        'default': [IsAdminRole]
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
    permission_classes_by_action = {'create': [IsAdminRole], 'list': [IsAdminRole], 'verify_otp': [AllowAny], 'default': [IsAdminRole]}

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
            user.is_staff = False
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
    permission_classes_by_action = {'create': [IsAdminRole], 'list': [IsAdminRole], 'verify_otp': [AllowAny], 'default': [IsAdminRole]}

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
    permission_classes_by_action = {'create': [IsAdminRole], 'list': [IsAdminRole], 'verify_otp': [AllowAny], 'default': [IsAdminRole]}

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


# ============================================================
# Staff management — admin can list/create/update/delete staff
# and change their roles (user_type).
# ============================================================
VALID_ROLES = ['admin', 'sales', 'accounts', 'hybrid']


class StaffViewSet(viewsets.ViewSet):
    """Full CRUD for staff. Admin only."""
    permission_classes_by_action = {
        'list': [IsAdminRole],
        'retrieve': [IsAdminRole],
        'create': [IsAdminRole],
        'update': [IsAdminRole],
        'partial_update': [IsAdminRole],
        'destroy': [IsAdminRole],
        'default': [IsAdminRole],
    }

    def get_permissions(self):
        return [p() for p in self.permission_classes_by_action.get(
            self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        search = (request.query_params.get('search') or '').strip()
        qs = UserAccount.objects.all().order_by('-added_on')
        if search:
            qs = qs.filter(
                Q(name__icontains=search) |
                Q(email__icontains=search) |
                Q(phone__icontains=search) |
                Q(user_type__icontains=search)
            )
        data = UserAccountSerializer(qs, many=True).data
        return Response({"error": False, "message": "Staff list", "data": data})

    def retrieve(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)
        return Response(UserAccountSerializer(user).data)

    def create(self, request):
        data = request.data
        name = (data.get('name') or '').strip()
        email = (data.get('email') or '').strip().lower()
        phone = (data.get('phone') or '').strip()
        user_type = (data.get('user_type') or 'sales').strip().lower()
        password = data.get('password')

        if not name:
            return Response({'error': 'Name is required'}, status=status.HTTP_400_BAD_REQUEST)
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({'error': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)
        if user_type not in VALID_ROLES:
            return Response({'error': f'Invalid role. Must be one of {VALID_ROLES}'},
                            status=status.HTTP_400_BAD_REQUEST)
        if UserAccount.objects.filter(email__iexact=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        user = UserAccount(
            name=name, email=email, phone=phone,
            user_type=user_type, is_active=True,
            is_staff=user_type == 'admin',
            is_superuser=user_type == 'admin',
        )
        user.password = make_password(password)
        user.save()
        return Response(UserAccountSerializer(user).data, status=status.HTTP_201_CREATED)

    def _apply_update(self, user, data, partial=False):
        if 'name' in data and data['name']:
            user.name = data['name'].strip()
        if 'email' in data and data['email']:
            new_email = data['email'].strip().lower()
            if UserAccount.objects.filter(email__iexact=new_email).exclude(pk=user.pk).exists():
                raise ValidationError('Email already exists')
            user.email = new_email
        if 'phone' in data:
            user.phone = (data.get('phone') or '').strip()
        if 'user_type' in data and data['user_type']:
            ut = data['user_type'].strip().lower()
            if ut not in VALID_ROLES:
                raise ValidationError(f'Invalid role. Must be one of {VALID_ROLES}')
            user.user_type = ut
            user.is_staff = ut == 'admin'
            user.is_superuser = ut == 'admin'
        if 'is_active' in data:
            user.is_active = bool(data['is_active'])
        if data.get('password'):
            user.password = make_password(data['password'])
        user.save()
        return user

    def update(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)
        try:
            user = self._apply_update(user, request.data, partial=False)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(UserAccountSerializer(user).data)

    def partial_update(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)
        try:
            user = self._apply_update(user, request.data, partial=True)
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(UserAccountSerializer(user).data)

    def destroy(self, request, pk=None):
        user = get_object_or_404(UserAccount, pk=pk)
        if request.user and request.user.pk == user.pk:
            return Response({'error': "You can't delete your own account"},
                            status=status.HTTP_400_BAD_REQUEST)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=['get'], url_path='roles')
    def roles(self, request):
        return Response({"data": [
            {"value": r, "label": r.capitalize()} for r in VALID_ROLES
        ]})
