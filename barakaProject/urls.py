"""
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from barakaApp.views import AdminUserViewSet, SalesUserViewSet, HybridUserViewSet

router = routers.DefaultRouter()
router.register(r'admin/users', AdminUserViewSet, basename='admin-user')
router.register(r'hybrid/users', HybridUserViewSet, basename='bar-user')
router.register(r'sales/users', SalesUserViewSet, basename='liquor-store-user')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/gettoken/', TokenObtainPairView.as_view(), name="gettoken"),
    path('api/refresh_token/', TokenRefreshView.as_view(), name="refresh_token"),
]
