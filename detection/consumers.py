# detection/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer

# Changed group name
PACKET_GROUP_NAME = 'live_packets'

class PacketConsumer(AsyncWebsocketConsumer): # Renamed class
    async def connect(self):
        await self.channel_layer.group_add(
            PACKET_GROUP_NAME, # Use new group name
            self.channel_name
        )
        await self.accept()
        print(f"Packet WebSocket connected: {self.channel_name}")

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            PACKET_GROUP_NAME, # Use new group name
            self.channel_name
        )
        print(f"Packet WebSocket disconnected: {self.channel_name}")

    # Renamed handler method to match the 'type' we will send
    async def packet_update(self, event):
        # This method is called when a message with 'type': 'packet.update'
        # is sent to the PACKET_GROUP_NAME group.
        message_data = event['data']
        print(f"CONSUMER: Received packet_update event: {message_data}")

        # Send message data down to the WebSocket client
        try:
            await self.send(text_data=json.dumps(message_data))
            print(f"CONSUMER: Sent packet data to WebSocket: {message_data}")
        except Exception as e:
             print(f"CONSUMER: Error sending packet data to WebSocket: {e}")
    pass

ALERT_GROUP_NAME = 'live_alerts'
class AlertConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Add this consumer to the 'live_alerts' group
        await self.channel_layer.group_add(
            ALERT_GROUP_NAME,
            self.channel_name
        )
        await self.accept()
        print(f"Alert WebSocket connected: {self.channel_name}")

    async def disconnect(self, close_code):
        # Remove consumer from the group
        await self.channel_layer.group_discard(
            ALERT_GROUP_NAME,
            self.channel_name
        )
        print(f"Alert WebSocket disconnected: {self.channel_name}")

    # Method to handle 'alert.created' messages
    async def alert_created(self, event):
        # Send the alert data received in the event to the WebSocket client
        alert_data = event['data']
        print(f"CONSUMER: Sending new alert data to WebSocket: {alert_data}")
        try:
            await self.send(text_data=json.dumps(alert_data))
        except Exception as e:
            print(f"CONSUMER: Error sending alert data to WebSocket: {e}")