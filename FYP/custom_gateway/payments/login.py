from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login
from django.contrib import messages

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
