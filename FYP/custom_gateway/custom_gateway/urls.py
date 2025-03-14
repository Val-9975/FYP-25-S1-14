from django.urls import path, include
from django.contrib.auth.views import LogoutView
from payments import views as payment_views
from payments.views import systemAdmin_dashboard
from payments.views import custom_logout
from payments.views import custom_login
from payments.views import merchant_dashboard
from payments.views import helpDesk_dashboard
from payments.views import customer_dashboard

urlpatterns = [
    path('login/', payment_views.custom_login, name='login'),
    path('logout/', custom_logout, name='logout'),
    path('customer_dashboard/', customer_dashboard, name='customer_dashboard'),
    path('systemAdmin_dashboard/', systemAdmin_dashboard, name='systemAdmin_dashboard'),
    path('merchant_dashboard/', merchant_dashboard, name='merchant_dashboard'),
    path('helpDesk_dashboard/', helpDesk_dashboard, name='helpDesk_dashboard'),
    path('payments/', include('payments.urls')),
]
