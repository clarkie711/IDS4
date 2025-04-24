# detection/routing.py
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    # Changed path from /ws/graph/ to /ws/packets/
    re_path(r'ws/packets/$', consumers.PacketConsumer.as_asgi()), # Renamed Consumer class
    re_path(r'ws/alerts/$', consumers.AlertConsumer.as_asgi()),
]