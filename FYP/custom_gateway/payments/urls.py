from django.urls import path
from . import views

urlpatterns = [
    path('pay/', views.process_payment, name='process_payment'),
    path('my-transactions/', views.user_transactions, name='user_transactions'),
    # Add the customer dashboard URL:
    path('dashboard/customer/', views.customer_dashboard, name='customer_dashboard'),
    path('dashboard/customer/viewPurchaseUI/', views.view_purchase, name='view_purchase'),
    path('dashboard/customer/contact/', views.contact_support, name='contact_support'),
    path('payments/transfer/', views.process_money_transfer, name='process_money_transfer'),
    
    path('dashboard/merchant/', views.merchant_dashboard, name='merchant_dashboard'),
    
]

