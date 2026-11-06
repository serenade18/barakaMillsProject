"""
"""
from importlib import import_module

from django.contrib import admin
from django.urls import path, include
from rest_framework import routers

# Each app under apps/ owns its routes; they are all mounted at the same
# /api/ prefix as before, so every URL is unchanged.
API_APPS = [
    'accounts',
    'farmers',
    'machines',
    'milling',
    'payments',
    'dashboard',
]

router = routers.DefaultRouter()
for app in API_APPS:
    router.registry.extend(import_module(f'apps.{app}.urls').router.registry)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
] + [path('api/', include(f'apps.{app}.urls')) for app in API_APPS]
