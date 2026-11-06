from django.urls import path
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.accounts.views import AdminUserViewSet, HybridUserViewSet, SalesUserViewSet, StaffViewSet, UserInfoView, \
    ChangePasswordView

router = routers.SimpleRouter()
router.register(r'admin/users', AdminUserViewSet, basename='admin-user')
router.register(r'hybrid/users', HybridUserViewSet, basename='bar-user')
router.register(r'sales/users', SalesUserViewSet, basename='liquor-store-user')
router.register(r'staff', StaffViewSet, basename='staff')

# Mounted under /api/
urlpatterns = [
    path('gettoken/', TokenObtainPairView.as_view(), name="gettoken"),
    path('refresh_token/', TokenRefreshView.as_view(), name="refresh_token"),
    path('admin/verify/', AdminUserViewSet.as_view({'post': 'verify_otp'}), name='admin-verify'),
    path('hybrid/verify/', HybridUserViewSet.as_view({'post': 'verify_otp'}), name='hybrid-verify'),
    path('sales/verify/', SalesUserViewSet.as_view({'post': 'verify_otp'}), name='sales-verify'),
    path('userinfo/', UserInfoView.as_view(), name='userinfo'),
    path('user/me/', UserInfoView.as_view(), name='user-info'),
    path('user/change-password/', ChangePasswordView.as_view(), name='change-password'),
]
