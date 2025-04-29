from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.contrib import messages
import random
from datetime import datetime

User = get_user_model()

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, 'Email not registered.')
            return render(request, 'forgetPassword.html')

        otp = random.randint(100000, 999999)
        request.session['fp_email'] = email
        request.session['fp_otp'] = otp
        request.session['fp_otp_created_at'] = datetime.now().timestamp()

        print(f"[DEBUG] Forgot Password OTP for {email}: {otp}")

        html_message = render_to_string('resetPasswordOtpEmail.html', {'otp': otp})
        plain_message = strip_tags(html_message)

        send_mail(
            subject='Your OTP for SafePay Password Reset',
            message=plain_message,
            from_email='safepay2025@gmail.com',
            recipient_list=[email],
            html_message=html_message,
            fail_silently=False,
        )

        return redirect('verify_otp_forgot')

    return render(request, 'forgetPassword.html')
