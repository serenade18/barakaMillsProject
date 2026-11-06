from django.urls import path
from rest_framework import routers

from apps.farmers.views import FarmerViewSet, FarmerOnlyViewSet, FarmerNameViewSet, TotalPositiveBalanceView, \
    TotalNegativeBalanceView, FarmersWithPositiveBalanceViewSet, FarmersWithNegativeBalanceViewSet

router = routers.SimpleRouter()
router.register(r'farmers', FarmerViewSet, basename='farmers')
router.register("debtors", FarmersWithPositiveBalanceViewSet, basename="debtors")
router.register("overdue", FarmersWithNegativeBalanceViewSet, basename="overdue")

# Mounted under /api/
urlpatterns = [
    path('farmeronly/', FarmerOnlyViewSet.as_view(), name="farmeronly"),
    path('farmername/', FarmerNameViewSet.as_view(), name="farmername"),
    path('farmers/farmers-with-balance/', FarmerViewSet.as_view({'get': 'farmers_with_balance'}), name='farmers-with-balance'),
    path('farmers/farmers-with-excess/', FarmerViewSet.as_view({'get': 'farmers_with_excess'}), name='farmers-with-excess'),
    path('farmers/total-balance/', FarmerViewSet.as_view({'get': 'total_balance'}), name='total-balance'),
    path('underpaid/', TotalPositiveBalanceView.as_view(), name="underpaid"),
    path('overpaid/', TotalNegativeBalanceView.as_view(), name="overpaid"),
]
