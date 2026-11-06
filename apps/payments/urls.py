from rest_framework import routers

from apps.payments.views import PaymentViewSet

router = routers.SimpleRouter()
router.register(r'payments', PaymentViewSet, basename='payments')

# Mounted under /api/
urlpatterns = []
