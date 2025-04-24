"""
ASGI config for ids_project project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

# ids_project/asgi.py
import os
import django
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack # Optional: If you need user auth in websockets
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ids_project.settings')
django.setup() # Ensure Django settings are loaded

# Import routing *after* django.setup()
import detection.routing

application = ProtocolTypeRouter({
  # Django's ASGI application to handle standard HTTP requests
  "http": get_asgi_application(),

  # WebSocket handler
  "websocket": AuthMiddlewareStack( # Use AuthMiddlewareStack if login needed for WS
      URLRouter(
          detection.routing.websocket_urlpatterns # Point to your app's routing
      )
  ),
})