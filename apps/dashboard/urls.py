from rest_framework import routers

from apps.dashboard.views import DashboardViewsSet, YearlyDataViewSet, MonthlyDataViewSet, \
    MonthlyMillsPerMachineViewSet, YearlyMillsPerMachineViewSet, DailyMillsPerMachineViewSet

router = routers.SimpleRouter()
router.register(r'dashboard', DashboardViewsSet, basename='dashboard')
router.register(r'yearly_chart', YearlyDataViewSet, basename="yearly_chart")
router.register(r'monthly_chart', MonthlyDataViewSet, basename="monthly_chart")
router.register(r'monthly_kilos_mill', MonthlyMillsPerMachineViewSet, basename="monthly_kilos_mill")
router.register(r'yearly_kilos_mill', YearlyMillsPerMachineViewSet, basename="yearly_kilos_mill")
router.register(r'daily_kilos_mill', DailyMillsPerMachineViewSet, basename="daily_kilos_mill")

# Mounted under /api/
urlpatterns = []
