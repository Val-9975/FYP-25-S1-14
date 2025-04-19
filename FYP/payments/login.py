from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.template.loader import render_to_string
from datetime import datetime
import random

def authenticate_user(request):
    email = request.POST.get('email')
    password = request.POST.get('password')
    user = authenticate(request, username=email, password=password)

    if user is not None:
        otp = random.randint(100000, 999999)

        # Store info in session
        request.session['otp'] = otp
        request.session['email'] = email
        request.session['password'] = password

        request.session['otp_created_at'] = datetime.now().timestamp()

        # Print OTP in terminal for debugging
        #print(f"[DEBUG] OTP for {email} is: {otp}")

        # Render HTML email from template
        html_message = render_to_string('otp_email.html', {'otp': otp})
        plain_message = strip_tags(html_message)

        send_mail(
            subject='Your OTP for SafePay Login',
            message=plain_message,
            from_email='safepay2025@gmail.com',
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )

        return True

    return False

def handle_login(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)

        if user is not None:
            login(request, user)  # Django manages the session automatically

            # Redirect based on user role
            role_redirects = {
                1: 'customer_dashboard',
                2: 'merchant_dashboard',
                3: 'systemAdmin_dashboard',
                4: 'helpDesk_dashboard'
            }
            return redirect(role_redirects.get(user.role_id, 'home'))
        else:
            messages.error(request, "Invalid email or password.")
            return render(request, 'login.html')

    return render(request, 'login.html')
