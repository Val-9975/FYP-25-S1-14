from django.contrib.auth import logout
from django.shortcuts import redirect

def custom_logout(request):
    # Clear session data
    request.session.flush()  # This clears the session completely

    # Log out the user
    logout(request)

    # Redirect to login page
    return redirect('handle_login')
