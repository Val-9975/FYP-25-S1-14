from django.contrib.auth import authenticate
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
