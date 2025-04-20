import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from payments.models import LegacyUser
from .models import HelpdeskAgent, Message

class HelpdeskConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Only allow helpdesk agents to connect
        if not await self.is_helpdesk_agent():
            await self.close()
            return
        
        self.user = self.scope['user']
        self.agent_group = "helpdesk_agents"
        
        # Add to helpdesk agents group
        await self.channel_layer.group_add(
            self.agent_group,
            self.channel_name
        )
        
        await self.update_agent_status(True)
        await self.accept()

    async def disconnect(self, close_code):
        if hasattr(self, 'agent_group'):
            await self.channel_layer.group_discard(
                self.agent_group,
                self.channel_name
            )
        await self.update_agent_status(False)

    @database_sync_to_async
    def is_helpdesk_agent(self):
        return hasattr(self.user, 'role_id') and self.user.role_id == 4

    @database_sync_to_async
    def update_agent_status(self, is_available):
        agent, created = HelpdeskAgent.objects.get_or_create(user=self.user)
        agent.is_available = is_available
        agent.save()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.user = self.scope['user']
        
        # For helpdesk agents (role_id=4)
        if await self.is_helpdesk_agent():
            await self.update_agent_status(True, self.room_name)
        
        await self.accept()

    async def disconnect(self, close_code):
        # For helpdesk agents
        if await self.is_helpdesk_agent():
            await self.update_agent_status(True, None)
        
        # Leave room group if needed
        if hasattr(self, 'room_group_name'):
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )

    @database_sync_to_async
    def is_helpdesk_agent(self):
        return hasattr(self.user, 'role_id') and self.user.role_id == 4

    @database_sync_to_async
    def update_agent_status(self, is_available, current_chat=None):
        agent, created = HelpdeskAgent.objects.get_or_create(user=self.user)
        agent.is_available = is_available
        agent.current_chat = current_chat
        agent.save()
    
    