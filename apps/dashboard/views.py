from collections import defaultdict
from datetime import date

from django.db.models import Sum, F, ExpressionWrapper, FloatField
from django.utils import timezone
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from apps.core.permissions import IsAdminRole
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication

from apps.farmers.models import Farmer
from apps.milling.models import Milled
from apps.payments.models import Payments


# Dashboard viewset
class DashboardViewsSet(viewsets.ViewSet):
    permission_classes_by_action = {
        'list': [IsAdminRole],
        'default': [IsAuthenticated]
    }

    def get_permissions(self):
        return [permission() for permission in
                self.permission_classes_by_action.get(self.action, self.permission_classes_by_action['default'])]

    def list(self, request):
        year = request.query_params.get('year')
        month = request.query_params.get('month')

        # ----- Farmers -----
        farmers = Farmer.objects.all()
        if year and month:
            farmers = farmers.filter(added_on__year=year, added_on__month=month)
        elif year:
            farmers = farmers.filter(added_on__year=year)

        # ----- Milled -----
        milled = Milled.objects.all()
        if year and month:
            milled = milled.filter(mill_date__year=year, mill_date__month=month)
        elif year:
            milled = milled.filter(mill_date__year=year)

        # Aggregate totals with ExpressionWrapper
        total_kgs = milled.aggregate(
            total_kgs=Sum(ExpressionWrapper(F('kgs'), output_field=FloatField()))
        )['total_kgs'] or 0

        total_amount = milled.aggregate(
            total_amount=Sum(ExpressionWrapper(F('amount'), output_field=FloatField()))
        )['total_amount'] or 0

        milling_revenue = milled.aggregate(
            revenue=Sum(
                ExpressionWrapper(
                    F('kgs') * F('price'),
                    output_field=FloatField()
                )
            )
        )['revenue'] or 0

        # ----- Payments -----
        payments = Payments.objects.all()
        if year and month:
            payments = payments.filter(added_on__year=year, added_on__month=month)
        elif year:
            payments = payments.filter(added_on__year=year)

        total_payment = payments.aggregate(
            total_payment=Sum(ExpressionWrapper(F('payment'), output_field=FloatField()))
        )['total_payment'] or 0

        total_balance = total_amount - total_payment

        return Response({
            "error": False,
            "message": "Home page data",
            "farmer_count": farmers.count(),
            "total_milled": total_kgs,
            "total_amount": total_amount,
            "total_payment": total_payment,
            "total_balance": total_balance,
            "milling_revenue": milling_revenue
        })


# Yearly kilos payment chart
class YearlyDataViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        year = request.query_params.get("year")
        month = request.query_params.get("month")

        # ======================
        # MILLED QUERYSET
        # ======================
        milled_qs = Milled.objects.all()

        if year:
            milled_qs = milled_qs.filter(mill_date__year=year)

        if month:
            milled_qs = milled_qs.filter(mill_date__month=month)

        year_dates = (
            milled_qs.order_by()
            .values("mill_date__year")
            .distinct()
        )

        year_kilos_chart_list = []
        year_revenue_chart_list = []

        for y in year_dates:
            access_year = y["mill_date__year"]

            year_data = milled_qs.filter(mill_date__year=access_year)

            year_kilos = sum(float(item.kgs) for item in year_data)
            year_revenue = sum(float(item.amount) for item in year_data)

            access_date = date(access_year, 1, 1)

            year_kilos_chart_list.append({
                "date": access_date,
                "kilos": year_kilos
            })

            year_revenue_chart_list.append({
                "date": access_date,
                "amt": year_revenue
            })

        # ======================
        # PAYMENTS QUERYSET
        # ======================
        payments_qs = Payments.objects.all()

        if year:
            payments_qs = payments_qs.filter(added_on__year=year)

        if month:
            payments_qs = payments_qs.filter(added_on__month=month)

        year_payment_dates = (
            payments_qs.order_by()
            .values("added_on__year")
            .distinct()
        )

        year_payments_chart_list = []

        for y in year_payment_dates:
            access_year = y["added_on__year"]

            year_data = payments_qs.filter(added_on__year=access_year)

            year_payment = sum(float(item.amount) for item in year_data)

            access_date = date(access_year, 1, 1)

            year_payments_chart_list.append({
                "date": access_date,
                "amt": year_payment
            })

        return Response({
            "error": False,
            "message": "Yearly Data",
            "year_kilos": year_kilos_chart_list,
            "year_payments": year_payments_chart_list,
            "year_revenue": year_revenue_chart_list,  # milling revenue
        })


# Monthly kilos and payment chart
class MonthlyDataViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        year = request.query_params.get("year")
        month = request.query_params.get("month")

        # Filter Milled
        milled_qs = Milled.objects.all()
        if year:
            milled_qs = milled_qs.filter(mill_date__year=year)
        if month:
            milled_qs = milled_qs.filter(mill_date__month=month)

        month_dates = milled_qs.order_by().values("mill_date__month", "mill_date__year").distinct()
        month_kilos_chart_list = []
        for m in month_dates:
            access_month = m["mill_date__month"]
            access_year = m["mill_date__year"]
            month_data = milled_qs.filter(mill_date__month=access_month, mill_date__year=access_year)
            month_kilos = sum(float(d.kgs) for d in month_data)
            month_kilos_chart_list.append({"date": date(access_year, access_month, 1), "kilos": month_kilos})

        # Filter Payments
        payments_qs = Payments.objects.all()
        if year:
            payments_qs = payments_qs.filter(added_on__year=year)
        if month:
            payments_qs = payments_qs.filter(added_on__month=month)

        month_payment_dates = payments_qs.order_by().values("added_on__month", "added_on__year").distinct()
        month_payments_chart_list = []
        for m in month_payment_dates:
            access_month = m["added_on__month"]
            access_year = m["added_on__year"]
            month_data = payments_qs.filter(added_on__month=access_month, added_on__year=access_year)
            month_payment = sum(float(p.amount) for p in month_data)
            month_payments_chart_list.append({"date": date(access_year, access_month, 1), "amt": month_payment})

        return Response({
            "error": False,
            "message": "Monthly Data",
            "month_kilos_chart": month_kilos_chart_list,
            "month_payments_chart": month_payments_chart_list
        })


# monthly kilos per machine
class MonthlyMillsPerMachineViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        milled_data = Milled.objects.all()
        grouped_kgs = defaultdict(lambda: defaultdict(float))  # {month: {machine_name: total_kgs}}
        grouped_amount = defaultdict(lambda: defaultdict(float))

        for record in milled_data:
            try:
                # Convert mill_date to 'YYYY-MM' format
                month_key = record.mill_date.strftime('%Y-%m')
                machine_name = record.machine_id.name
                kgs = float(record.kgs)
                amount = float(record.amount)

                grouped_kgs[month_key][machine_name] += kgs
                grouped_amount[month_key][machine_name] += amount
            except (ValueError, AttributeError):
                continue

        monthly_mills_chart = []
        for month_key, machines in grouped_kgs.items():
            entry = {"month": month_key}
            entry.update(machines)  # Flatten machine totals into the same dict
            monthly_mills_chart.append(entry)

        # Prepare chart data for amount
        monthly_mills_amount_chart = []
        for month_key, machines in grouped_amount.items():
            entry = {"month": month_key}
            entry.update(machines)
            monthly_mills_amount_chart.append(entry)

        return Response({
            "error": False,
            "message": "Monthly Mills Per Machine",
            "monthly_mills": monthly_mills_chart,
            "monthly_mills_amount": monthly_mills_amount_chart
        })


# monthly kilos per machine
class YearlyMillsPerMachineViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        milled_data = Milled.objects.all()
        grouped_kgs = defaultdict(lambda: defaultdict(float))  # {month: {machine_name: total_kgs}}
        grouped_amount = defaultdict(lambda: defaultdict(float))

        for record in milled_data:
            try:
                # Convert mill_date to 'YYYY-MM' format
                year_key = record.mill_date.strftime('%Y')
                machine_name = record.machine_id.name
                kgs = float(record.kgs)
                amount = float(record.amount)

                grouped_kgs[year_key][machine_name] += kgs
                grouped_amount[year_key][machine_name] += amount
            except (ValueError, AttributeError):
                continue

        yearly_mills_chart = []
        for year_key, machines in grouped_kgs.items():
            entry = {"year": year_key}
            entry.update(machines)  # Flatten machine totals into the same dict
            yearly_mills_chart.append(entry)

        # Prepare chart data for amount
        yearly_mills_amount_chart = []
        for year_key, machines in grouped_amount.items():
            entry = {"year": year_key}
            entry.update(machines)
            yearly_mills_amount_chart.append(entry)

        return Response({
            "error": False,
            "message": "Monthly Mills Per Machine",
            "yearly_mills": yearly_mills_chart,
            "yearly_mills_amount": yearly_mills_amount_chart
        })


# daily kilos per machine (today)
class DailyMillsPerMachineViewSet(viewsets.ViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def list(self, request):
        from datetime import date as _date
        target_str = request.query_params.get("date")
        try:
            target = _date.fromisoformat(target_str) if target_str else timezone.now().date()
        except ValueError:
            target = timezone.now().date()

        milled_data = Milled.objects.filter(mill_date=target).select_related("machine_id")
        grouped_kgs = defaultdict(float)
        grouped_amount = defaultdict(float)
        machine_ids = {}

        for record in milled_data:
            try:
                machine_name = record.machine_id.name
                machine_ids[machine_name] = record.machine_id.id
                grouped_kgs[machine_name] += float(record.kgs)
                grouped_amount[machine_name] += float(record.amount)
            except (ValueError, AttributeError):
                continue

        daily_mills = [
            {"machine_id": machine_ids[name], "machine": name, "kilos": kgs, "amount": grouped_amount.get(name, 0)}
            for name, kgs in grouped_kgs.items()
        ]

        return Response({
            "error": False,
            "message": "Daily Mills Per Machine",
            "date": target.isoformat(),
            "daily_mills": daily_mills,
        })
