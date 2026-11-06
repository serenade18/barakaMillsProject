from django.urls import path
from rest_framework import routers

from apps.machines.views import MachineViewSet, MachineOnlyViewSet, MachineNameViewSet

router = routers.SimpleRouter()
router.register(r'machines', MachineViewSet, basename='machines')

# Mounted under /api/
urlpatterns = [
    path('machineonly/', MachineOnlyViewSet.as_view(), name="machineonly"),
    path('machinename/', MachineNameViewSet.as_view(), name="machinename"),
]
