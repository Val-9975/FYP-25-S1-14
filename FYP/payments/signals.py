# signals.py
from django.contrib.auth import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from .models import HelpdeskAgent

@receiver(user_logged_in)
def set_agent_available(sender, request, user, **kwargs):
    # Only activate if this is a POST-login (after OTP verification)
    if request.path != '/verify-otp/':  # Adjust to your verify OTP URL
        return
        
    if hasattr(user, 'role_id') and user.role_id == 4:
        HelpdeskAgent.objects.update_or_create(
            user=user,
            defaults={
                'is_available': True,
                'last_login': timezone.now()
            }
        )

@receiver(user_logged_out)
def set_agent_unavailable(sender, request, user, **kwargs):
    if hasattr(user, 'role_id') and user.role_id == 4:
        HelpdeskAgent.objects.filter(user=user).update(
            is_available=False,
            last_logout=timezone.now()
        )