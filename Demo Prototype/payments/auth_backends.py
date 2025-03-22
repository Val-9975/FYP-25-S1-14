from django.contrib.auth.backends import BaseBackend
from .models import LegacyUser

class LegacyBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = LegacyUser.objects.get(email=username)
            # Compare plain text (for demonstration only; in production use hashing)
            if user.password == password:
                return user
        except LegacyUser.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return LegacyUser.objects.get(pk=user_id)
        except LegacyUser.DoesNotExist:
            return None
