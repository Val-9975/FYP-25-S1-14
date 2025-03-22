from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login
from django.contrib import messages
import random

def authenticate_user(request):
    email = request.POST.get('email')
    password = request.POST.get('password')
    user = authenticate(request, username=email, password=password)

    if user is not None:
        # Generate OTP
        otp = random.randint(100000, 999999)
        
        # Store data in session
        request.session['otp'] = otp
        request.session['email'] = email
        request.session['password'] = password  # Optional

        print(f"Your OTP is: {otp}")  # Display OTP in terminal
        return True  # Indicates successful authentication

    return False  # Indicates failure

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
