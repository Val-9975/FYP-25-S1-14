"""
ASGI config for custom_gateway project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
#from chat import routing  # Make sure this matches your chat app's routing module

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'custom_gateway.settings')  # Keep your original settings

# Initialize Django ASGI application early to ensure AppRegistry is populated
django_asgi_app = get_asgi_application()

application = ProtocolTypeRouter({
    "http": django_asgi_app,  # Your existing Django views
    "websocket": AuthMiddlewareStack(  # Your new chat functionality
        URLRouter(
            routing.websocket_urlpatterns
        )
    ),
})