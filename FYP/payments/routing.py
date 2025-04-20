from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    # Helpdesk agent monitoring connection
    re_path(r'ws/helpdesk/$', consumers.HelpdeskConsumer.as_asgi()),
    
    # Chat room connection with more specific pattern
    re_path(r'ws/chat/(?P<room_name>chat_\d+_\d+)/$', consumers.ChatConsumer.as_asgi()),
    
    # Fallback pattern (if you need to support other room name formats)
    re_path(r'ws/chat/(?P<room_name>[^/]+)/$', consumers.ChatConsumer.as_asgi()),
]