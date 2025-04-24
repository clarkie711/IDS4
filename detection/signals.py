# detection/signals.py
import json
import time
from django.db.models.signals import post_save
from django.dispatch import receiver
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import Alert

ALERT_GROUP_NAME = 'live_alerts' # Ensure this matches consumer

@receiver(post_save, sender=Alert) # Decorator listens for Alert saves
def alert_post_save_handler(sender, instance, created, **kwargs):
    """
    Sends alert data to the Channels group when a new Alert is created.
    """
    if created: # Only run when a new Alert is CREATED
        print(f"SIGNAL: New Alert created (ID: {instance.id}), sending via Channels...")
        channel_layer = get_channel_layer()
        if channel_layer:
            # Prepare data payload (match what the template JS expects)
            alert_data = {
                'id': instance.id,
                'timestamp': instance.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                'alert_type_code': instance.alert_type, # e.g., 'DDOS'
                'alert_type_display': instance.get_alert_type_display(), # e.g., 'DDoS Rate Exceeded'
                'source_ip': instance.source_ip,
                'destination_ip': instance.destination_ip,
                'destination_port': instance.destination_port,
                'details': instance.details,
                'http_payload': instance.http_payload,
            }

            message = {
                'type': 'alert.created', # Matches method name in AlertConsumer
                'data': alert_data
            }

            try:
                async_to_sync(channel_layer.group_send)(ALERT_GROUP_NAME, message)
                print(f"SIGNAL: Sent alert {instance.id} to group {ALERT_GROUP_NAME}")
            except Exception as e:
                print(f"SIGNAL: Error sending alert {instance.id} to channel layer: {e}")
        else:
            print("SIGNAL: Channel layer not available, cannot send alert.")
