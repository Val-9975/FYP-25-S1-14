from django.urls import path
from . import views
from payments.views import submit_complaint
from .forget_password import forgot_password

urlpatterns = [
    path('create-user/', views.create_user, name='create_user'),
    path('pay/', views.process_payment, name='process_payment'),
    path('my-transactions/', views.user_transactions, name='user_transactions'),
    path('change-password/', views.change_passwordProfile, name='change_passwordProfile'),
    path('forgot-password/', forgot_password, name='forgot_password'),
    path('verify-otp-forgot/', views.verify_otp_forgot, name='verify_otp_forgot'),
    path('reset-password/', views.reset_password, name='reset_password'),
    # Add the customer dashboard URL:
    path('dashboard/customer/', views.customer_dashboard, name='customer_dashboard'),
    path('dashboard/customer/viewPurchaseUI/', views.view_purchase, name='view_purchase'),
    path('dashboard/customer/contact/', views.contact_support, name='contact_support'),
    path('dashboard/customer/top-up-wallet/', views.top_up_wallet, name='top_up_wallet'),
    path('dashboard/customer/customer_profile/', views.customer_profile, name='customer_profile'),
    path('payments/transfer/', views.process_money_transfer, name='process_money_transfer'),
    path('dashboard/get-saved-payment-methods/', views.get_saved_payment_methods, name='get_saved_payment_methods'),
    path('payment-methods/<int:card_id>/', views.get_saved_card_detail, name='get_saved_card_detail'),
    path('delete-saved-card/<int:card_id>/', views.delete_saved_card, name='delete_saved_card'),
    path('contact/submit_complaint/', views.submit_complaint, name='submit_complaint'),
    path('complaint/success/', views.complaint_success, name='complaint_success'),


    
    # Add merchant dashboard URL:
    path('dashboard/merchant/', views.merchant_dashboard, name='merchant_dashboard'),
    path('dashboard/merchant/contact/', views.contact_support, name='contact_support_merchant'),
    path('dashboard/merchant/profile/', views.merchant_profile, name='merchant_profile'),
    
    # Add Admin stuff here
    path('dashboard/systemadmin/viewTransactions/', views.sysadmin_view_transactions, name='sysadmin_view_transactions'),
    path('dashboard/systemadmin/', views.systemAdmin_dashboard, name='sysadmin_dashboard'),
    path('dashboard/systemadmin/manage-users/', views.sysadmin_manage_users, name='sysadmin_manage_users'),
    path('dashboard/systemadmin/settings/', views.sysadmin_settings, name='sysadmin_settings'),
    path('dashboard/sysadmin/settings/', views.sysadmin_settings, name='sysadmin_settings'),
    path('dashboard/update-security-protocol-text/', views.update_security_protocol_text, name='update_security_protocol_text'),
    path('dashboard/systemadmin/update-security/', views.update_security_protocols, name='update_security_protocols'),
    path('dashboard/systemadmin/update-user-status/', views.update_user_status, name='update_user_status'),
    path('dashboard/systemadmin/view-user-logs/', views.sysadmin_view_user_logs, name='sysadmin_view_user_logs'),
    path('suspend-customer/', views.suspend_customer, name='suspend_customer'),
    path('login/', views.handle_login, name='login'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('dashboard/sysAdmin/complaints/', views.complaints_view, name='complaints_view'),
    path('dashboard/sysAdmin/submit_complaint/viewSubmittedComplaints', views.view_submitted_complaints, name='view_submitted_complaints'),
    # Helpdesk stuff
    path('dashboard/Helpdesk/Tickets/', views.view_tickets, name='view_tickets'),
    path('dashboard/Helpdesk/TicketsDetails/<int:ticket_id>/', views.ticket_details, name='ticket_details'),
    path('dashboard/helpdesk/', views.helpDesk_dashboard, name='helpdesk_dashboard'),
    path('dashboard/Helpdesk/LiveChat/', views.helpDesk_dashboard, name='live_chat'),
    path('dashboard/Helpdesk/LiveChat/', views.live_chat, name='live_chat'),
    path('dashboard/Helpdesk/Settings/', views.helpdesk_settings, name='helpdesk_settings'),
    path('dashboard/Helpdesk/Profile/', views.helpdesk_profile, name='helpdesk_profile'),
    path('helpdesk/analytics/', views.complaint_analytics, name='complaint_analytics'),

]

