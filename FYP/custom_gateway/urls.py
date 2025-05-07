from django.urls import path, include
from django.contrib.auth.views import LogoutView
from payments import views as payment_views
from payments.views import systemAdmin_dashboard
from payments.views import custom_logout
from payments.views import merchant_dashboard
from payments.views import helpDesk_dashboard
from payments.views import customer_dashboard
from payments.views import create_user
from payments.views import verify_otp
from payments.views import handle_login
from payments.views import home

urlpatterns = [
    path('', home, name='home'),
    path('login/', handle_login, name='handle_login'),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('logout/', custom_logout, name='logout'),
    path('create_user/', create_user, name='create_user'),
    path('customer_dashboard/', customer_dashboard, name='customer_dashboard'),
    path('systemAdmin_dashboard/', systemAdmin_dashboard, name='systemAdmin_dashboard'),
    path('merchant_dashboard/', merchant_dashboard, name='merchant_dashboard'),
    path('Helpdesk_dashboard/', helpDesk_dashboard, name='helpDesk_dashboard'),
    path('payments/', include('payments.urls')),
]
