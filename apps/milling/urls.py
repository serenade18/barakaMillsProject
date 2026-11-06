from rest_framework import routers

from apps.milling.views import MilledViewSet

router = routers.SimpleRouter()
router.register(r'milling', MilledViewSet, basename='milling')

# Mounted under /api/
urlpatterns = []
