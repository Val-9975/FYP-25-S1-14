from django.core.exceptions import PermissionDenied
from functools import wraps

# Define role constants (should match your database)
ROLE_CUSTOMER = 1
ROLE_MERCHANT = 2
ROLE_ADMIN = 3
ROLE_HELPDESK = 4

def role_required(*allowed_role_ids):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                raise PermissionDenied("You must be logged in.")
            
            # Check if the user's role_id is in the allowed roles
            if request.user.role_id not in allowed_role_ids:
                raise PermissionDenied("You do not have permission to access this page.")
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator