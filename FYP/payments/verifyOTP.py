from django.contrib.auth import authenticate, login
from payments.models import UserAccountStatus

def verify_otp_user(request):
    entered_otp = request.POST.get('otp')
    stored_otp = request.session.get('otp')

    if stored_otp and int(entered_otp) == stored_otp:
        email = request.session.get('email')
        password = request.session.get('password')

        user = authenticate(request, username=email, password=password)
        if user is not None:
            login(request, user)

            # Redirect based on role
            role_redirects = {
                1: 'customer_dashboard',
                2: 'merchant_dashboard',
                3: 'systemAdmin_dashboard',
                4: 'helpDesk_dashboard'
            }

            # Clear session data
            request.session.pop('otp', None)
            request.session.pop('email', None)
            request.session.pop('password', None)

            return role_redirects.get(user.role_id, 'home')

    return None  # Indicates invalid OTP
