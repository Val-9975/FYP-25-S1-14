from django.urls import path
from . import views
from payments.views import submit_complaint

urlpatterns = [
    path('create-user/', views.create_user, name='create_user'),
    path('pay/', views.process_payment, name='process_payment'),
    path('my-transactions/', views.user_transactions, name='user_transactions'),
    # Add the customer dashboard URL:
    path('dashboard/customer/', views.customer_dashboard, name='customer_dashboard'),
    path('dashboard/customer/viewPurchaseUI/', views.view_purchase, name='view_purchase'),
    path('dashboard/customer/contact/', views.contact_support, name='contact_support'),
    path('dashboard/customer/top-up-wallet/', views.top_up_wallet, name='top_up_wallet'),
    path('payments/transfer/', views.process_money_transfer, name='process_money_transfer'),
    path('support/live_chat/', views.initiate_chat, name='start_chat'),
    path('logout/', views.custom_logout, name='logout'),
    
    # Add merchant dashboard URL:
    path('dashboard/merchant/', views.merchant_dashboard, name='merchant_dashboard'),
    path('dashboard/merchant/contact/', views.contact_support, name='contact_support_merchant'),
    
    # Add Admin stuff here
    path('dashboard/systemadmin/viewTransactions/', views.sysadmin_view_transactions, name='sysadmin_view_transactions'),
    path('dashboard/systemadmin/', views.systemAdmin_dashboard, name='sysadmin_dashboard'),
    path('dashboard/systemadmin/manage-users/', views.sysadmin_manage_users, name='sysadmin_manage_users'),
    path('dashboard/systemadmin/settings/', views.sysadmin_settings, name='sysadmin_settings'),
    path('dashboard/systemadmin/update-security/', views.update_security_protocols, name='update_security_protocols'),
    path('dashboard/systemadmin/update-user-status/', views.update_user_status, name='update_user_status'),
    path('dashboard/systemadmin/view-user-logs/', views.sysadmin_view_user_logs, name='sysadmin_view_user_logs'),
    path('suspend-customer/', views.suspend_customer, name='suspend_customer'),
    path('login/', views.handle_login, name='login'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('dashboard/sysAdmin/complaints/', views.complaints_view, name='complaints_view'),
    path('dashboard/sysAdmin/submit_complaint/', views.submit_complaint, name='submit_complaint'),
    path('dashboard/sysAdmin/submit_complaint/viewSubmittedComplaints', views.view_submitted_complaints, name='view_submitted_complaints'),
    # Helpdesk stuff
    path('dashboard/Helpdesk/Tickets/', views.view_tickets, name='view_tickets'),
    path('dashboard/Helpdesk/TicketsDetails/<int:ticket_id>/', views.ticket_details, name='ticket_details'),
    path('dashboard/helpdesk/', views.helpDesk_dashboard, name='helpdesk_dashboard'),
    path('dashboard/Helpdesk/LiveChat/', views.helpDesk_dashboard, name='live_chat'),
    path('dashboard/Helpdesk/LiveChat/', views.live_chat, name='live_chat'),
    path('dashboard/Helpdesk/Settings/', views.helpdesk_settings, name='helpdesk_settings'),
    path('dashboard/Helpdesk/chat/<str:room_name>/', views.chat_room, name='chat'),

]

