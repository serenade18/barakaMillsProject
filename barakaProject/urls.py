"""
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from barakaApp.views import AdminUserViewSet, SalesUserViewSet, HybridUserViewSet, UserInfoView, FarmerViewSet

router = routers.DefaultRouter()
router.register(r'admin/users', AdminUserViewSet, basename='admin-user')
router.register(r'hybrid/users', HybridUserViewSet, basename='bar-user')
router.register(r'sales/users', SalesUserViewSet, basename='liquor-store-user')
router.register(r'farmers', FarmerViewSet, basename='farmers')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/gettoken/', TokenObtainPairView.as_view(), name="gettoken"),
    path('api/refresh_token/', TokenRefreshView.as_view(), name="refresh_token"),
    path('api/admin/verify/', AdminUserViewSet.as_view({'post': 'verify_otp'}), name='admin-verify'),
    path('api/hybrid/verify/', HybridUserViewSet.as_view({'post': 'verify_otp'}), name='hybrid-verify'),
    path('api/sales/verify/', SalesUserViewSet.as_view({'post': 'verify_otp'}), name='sales-verify'),
    path('api/userinfo/', UserInfoView.as_view(), name='userinfo'),
]
