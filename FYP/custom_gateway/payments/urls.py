from django.urls import path
from . import views
from payments.views import submit_complaint

urlpatterns = [
    path('pay/', views.process_payment, name='process_payment'),
    path('my-transactions/', views.user_transactions, name='user_transactions'),
    
    # Add the customer dashboard URL:
    path('dashboard/customer/', views.customer_dashboard, name='customer_dashboard'),
    path('dashboard/customer/viewPurchaseUI/', views.view_purchase, name='view_purchase'),
    path('dashboard/customer/contact/', views.contact_support, name='contact_support'),
    path('payments/transfer/', views.process_money_transfer, name='process_money_transfer'), 
    
    # Add merchant dashboard URL:
    path('dashboard/merchant/', views.merchant_dashboard, name='merchant_dashboard'),
    path('dashboard/merchant/contact/', views.contact_support, name='contact_support_merchant'),
    
    #Add SysAdmin dashboard URL
    path('dashboard/sysAdmin/', views.systemAdmin_dashboard, name='systemAdmin_dashboard'),
    path('dashboard/sysAdmin/complaints/', views.complaints_view, name='complaints_view'),
    path('dashboard/sysAdmin/submit_complaint/', views.submit_complaint, name='submit_complaint'),
    path('dashboard/sysAdmin/submit_complaint/viewSubmittedComplaints', views.view_submitted_complaints, name='view_submitted_complaints'),

]

