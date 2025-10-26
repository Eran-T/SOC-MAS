import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import socketio
import logging
from contextlib import asynccontextmanager
import os
from collections import deque
import threading
import asyncio

from typing import Iterable
import json
from a2a.client.client import Client
from a2a.client import A2AClient, A2ACardResolver, ClientConfig, ClientFactory
from google.adk.sessions import VertexAiSessionService
from a2a.types import (
    SendMessageRequest,
    MessageSendParams,
    JSONRPCErrorResponse,
    Message,
    AgentCard,
    Task,
    TextPart,
    TaskState,
    TransportProtocol
)
import traceback
from uuid import uuid4
from google.auth import default
from google.auth.transport.requests import Request as Request_
from a2a.client.middleware import ClientCallContext
import random
import sys
from google.genai.types import HttpOptions
import vertexai



from a2a.auth.user import UnauthenticatedUser, User


CHAT_AGENT_SERVER_URL = os.environ.get('CHAT_AGENT_SERVER_URL')
LOCATION = os.environ.get('REGION')
GOOGLE_CLOUD_PROJECT = os.environ.get('GOOGLE_CLOUD_PROJECT')
# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Socket.IO server
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
# FastAPI app
app = FastAPI()
# Class to manage agent conenction


class GoogleAuthRefresh(httpx.Auth):
    def __init__(self, scopes):
        self.credentials, _ = default(scopes=scopes)
        self.transport_request = Request_()
        self.credentials.refresh(self.transport_request)

    def auth_flow(self, request):
        if not self.credentials.valid:
            self.credentials.refresh(self.transport_request)
        
        request.headers['Authorization'] = f'Bearer {self.credentials.token}'
        yield request

factory = ClientFactory(
    ClientConfig(
        supported_transports=[TransportProtocol.http_json],
        use_client_preference=True,
        httpx_client=httpx.AsyncClient(
            timeout=120,
            headers={
                'Content-Type': 'application/json',
            },
            auth=GoogleAuthRefresh(scopes=['https://www.googleapis.com/auth/cloud-platform']) 
        ),
    )
)

class AgentManagement:
    def __init__(self, socketio_instance, event_queue: deque, queue_lock: threading.Lock):
        self.socketio = socketio_instance
        self.available_agents: dict[str, Client] = {}
        self.available_agents_cards: dict[str, AgentCard] = {}
        self.agents = ""
        self.event_queue = event_queue
        self.queue_lock = queue_lock
        self.context = None
        self.task = None
        self.user_id = None



    async def initialize_available_agents(self, remote_agent_addresses: list[str]):
        for address in remote_agent_addresses:
            try:
                await self.get_agent_card(address)
            except Exception as e:
                logging.error(f"Failed to initialize agent at {address}: {e},  {traceback.format_exc()}")

    async def get_agent_card(self, address):
        logging.info(f"Getting agent card from: {address}")
        resolver = A2ACardResolver(base_url=address, httpx_client=httpx.AsyncClient(auth=GoogleAuthRefresh(scopes=['https://www.googleapis.com/auth/cloud-platform'])), agent_card_path='v1/card')
        card = await resolver.get_agent_card()
        self.register_agent_card(card)

    def register_agent_card(self, card: AgentCard):
        #card.url = card.url.replace('/a2a', '')
        remote_connection = factory.create(card)
        #A2AClient(httpx_client=httpx.AsyncClient(timeout=120, auth=GoogleAuthRefresh(scopes=['https://www.googleapis.com/auth/cloud-platform'])), agent_card=card)
        self.available_agents[card.name] = remote_connection
        self.available_agents_cards[card.name] = card
        agent_info = [json.dumps(ra) for ra in self.list_remote_agents()]
        self.agents = '\n'.join(agent_info)
        logging.info(f"Registered agent: {card.name}")

    def list_remote_agents(self):
        return [{'name': card.name, 'description': card.description} for card in self.available_agents_cards.values()]

    def _emit_event(self, from_agent: str, to_agent: str, message: str, is_final: bool = False):
        event = {"from": from_agent, "to": to_agent, "message": message, "final": is_final}
        asyncio.create_task(self.socketio.emit('new_event', event))
        logging.info(f"Emitted Event: {event}")

    def _queue_event(self, from_agent: str, to_agent: str, event_type: str,  message: str, is_final: bool = False):
        event = {"from": from_agent, "to": to_agent, "event": event_type, "message": message, "final": is_final}
        with self.queue_lock:
            self.event_queue.append(event)
        asyncio.create_task(self.socketio.emit('new_step_ready'))
        logging.info(f"Queued Event: {event}")

    def reset(self):
        self.context = None
        self.task = None


    async def send_message(self, message_text: str, agent_name='chat_agent', verbose=True):
        if agent_name not in self.available_agents:
            logging.error(f'Agent {agent_name} not found')
            self._emit_event("chat agent", "user", f"Error: The agent '{agent_name}' is not available.", True)
            return

        client = self.available_agents[agent_name]
        try:
            # 1. User -> Orchestrator
            if verbose:
                self._queue_event("user", "chat agent", "User Input", f'User said: "{message_text}"')
            if not self.context:
                session_service=VertexAiSessionService(GOOGLE_CLOUD_PROJECT, location=LOCATION)
                session = await session_service.create_session(app_name=CHAT_AGENT_SERVER_URL.replace('/a2a', '').replace(f'https://{LOCATION}-aiplatform.googleapis.com/v1beta1/',''), user_id=self.user_id)
                self.context = session.id


       

            request = Message(
                    role='user',
                    parts=[TextPart(text=message_text)],
                    messageId=str(uuid4()),
                    contextId=self.context
                )
            # state has http_kwargs which is processed as :context.state.get('http_kwargs') if context else None
            req = request.model_dump()
            part_segments = ['text', 'file', 'data', 'metadata']
            req['content'] = [{k: v for k, v in part.items() if k in part_segments} for part in req.pop('parts')]
            fields = ['messageId', 'contextId', 'taskId', 'role', 'content']
            req = {k: v for k, v in req.items() if k in fields}
            req['role'] = "ROLE_USER"

            content = { 
                    "configuration": {"blocking": True},
                    "metadata": {"user_id": self.user_id},
                    "message": req
                }
            content_bytes = json.dumps(content).encode('utf-8')
            context = ClientCallContext(state={'http_kwargs': {"content": content_bytes}})
            
            initial_response = client.send_message(request=request, context=context)


            # This will hold the last Task or Message object received,
            # which we'll process for artifacts at the end.
            final_response_object: Task | Message | None = None
            response_string = ""
            #print("❌❌❌❌initial_response: ", initial_response)
            # Iterate over the asynchronous stream of events
            async for event in initial_response:
                #print("❌❌❌❌event:❌❌❌❌ ", event)
                if isinstance(event, (list, tuple)):  # This is ClientEvent = tuple[Task, UpdateEvent]
                    task, update_event = event
                    final_response_object = task  # Store the latest task
                    
                    # Update context and task ID from the streaming task object
                    if task.context_id and not self.context:
                        self.context = task.context_id
                        #print(f"❌❌❌❌❌❌❌ self.context: {self.context}❌❌❌❌❌❌❌")
                    
                    # if task.status.state not in [
                    #     TaskState.completed,
                    #     TaskState.canceled,
                    #     TaskState.failed,
                    #     TaskState.unknown,
                    # ]:
                    #     self.task = task.id
                    # else:
                    #     self.task = None

                elif isinstance(event, Message):
                    # This is likely the final Message object.
                    final_response_object = event
                    
                    # Also update context/task info, assuming Message has similar attributes
                    if hasattr(event, 'context_id') and not event.context_id:
                        #print(f"❌❌❌❌❌❌❌ changing context to {event.context_id} ❌❌❌❌❌❌❌")
                        self.context = event.context_id
                    
                    # if hasattr(event, 'status') and event.status.state not in [
                    #     TaskState.completed,
                    #     TaskState.canceled,
                    #     TaskState.failed,
                    #     TaskState.unknown,
                    # ]:
                    #     if hasattr(event, 'id'):
                    #         self.task = event.id
                    # else:
                    #     self.task = None

            # After the loop, process the artifacts from the last object we received
            if final_response_object:
                print("resp: ", final_response_object)
                
                # Check for artifacts (assuming both Task and Message can have them)
                if hasattr(final_response_object, 'artifacts') and final_response_object.artifacts:
                    # Process the last artifact
                    for part in final_response_object.artifacts[-1].parts:
                        if part.root.kind == "text":
                            response_string = response_string + ' ' + part.root.text
                        elif (part.root.kind == 'data' and part.root.metadata) and (part.root.metadata.get('adk_type', None) == 'function_response') and (part.root.data['name'] != 'transfer_to_agent'):
                            print("part.root.data['name']:",part.root.data['name'])
                            print("HERE: ", part.root.data.get("response", {"result": ''}).get('result'))
                            response_string = response_string + ' ' + part.root.data.get("response", {"result": ''}).get('result')
                    response_string = response_string.lstrip()
                else:
                    print("Final response object had no artifacts to process.")
            
            else:
                # This case handles if the iterator finishes without yielding anything
                print("No final response or task received from stream.")

            # Queue the final response string
            self._queue_event("chat agent", "user", "model response", response_string, is_final=True)

        except Exception as e:
            # This block will now catch errors that occur during the iteration,
            # which likely replaces the old JSONRPCErrorResponse check.
            print(f"error in send_message: {e}, {traceback.format_exc()}")
            # You may want to queue an error event here
            # self._queue_event("chat agent", "user", "model response", f"Error: {e}", is_final=True)

app.mount("/templates", StaticFiles(directory="templates"), name="templates")

# Serve the main HTML at root "/"
@app.get("/", response_class=HTMLResponse)
async def root():
    # Adjust path as needed: try 'static/index.html'
    with open("templates/index.html") as f:
        return HTMLResponse(f.read())

# --- Event Queue and Agent Manager (shared objects) ---
event_queue = deque()
queue_lock = threading.Lock()
agent_manager = AgentManagement(sio, event_queue, queue_lock)

# --- HTTP Endpoints ---
@app.post("/event")
async def handle_generic_event(request: Request):
    data = await request.json()
    caller, called, event_type, event_data = (
        data.get("caller"), data.get("called"), data.get("event"), data.get("data")
    )
    if not all([caller, called, event_type, event_data]):
        return JSONResponse({"status": "error", "message": "Missing required fields."}, status_code=400)
    message = f"Tool Call: `{event_data}`" if event_type == "tool_call" else f"Message: \"{event_data}\""
    with queue_lock:
        event_queue.append({"from": caller, "to": called, "event": event_type, "message": message, "final": False})
    await sio.emit('new_step_ready')
    logging.info(f"Queued Generic Event: from={caller}, to={called}, message='{message}'")
    return JSONResponse({"status": "event queued"})

@app.post("/next_event")
async def next_event():
    with queue_lock:
        if not event_queue:
            return JSONResponse({"status": "empty", "message": "Event queue is empty."})
        event = event_queue.popleft()
        has_more_events = len(event_queue) > 0
    await sio.emit('new_event', event)
    logging.info(f"Emitted Next Event: {event}")
    return JSONResponse({"status": "event sent", "has_more_events": has_more_events})

@app.post("/chat")
async def handle_chat(request: Request):
    data = await request.json()
    user_message = data.get('message')
    user_id = data.get('user_id')
    session_id = data.get('session_id')
    #print(f"✅✅✅✅✅✅✅ user_id: {user_id} ✅✅✅✅✅✅✅")
    if not user_message:
        return JSONResponse({"status": "error", "message": "No message provided."}, status_code=400)
    logging.info(f"Received chat message: '{user_message}'. Starting agent task.")
    if not agent_manager.context:
        agent_manager.context = session_id
    if not agent_manager.user_id:
        agent_manager.user_id = user_id
    await agent_manager.send_message(user_message)#agent_manager.send_message(user_message, tool_context_dummy)
    
    return JSONResponse({"status": "agent task started",
                         "session_id": agent_manager.context,
                         "user_id": agent_manager.user_id})

@app.post("/reset")
async def reset():
    
    with queue_lock:
        event_queue.clear()
    agent_manager.reset()
    return JSONResponse({"status": "reset successful"})

# --- Socket.IO handlers (for logging connections) ---
@sio.event
async def connect(sid, environ, auth):
    logging.info(f'Client connected via WebSocket: {sid}')

@sio.event
async def disconnect(sid):
    logging.info(f'Client disconnected from WebSocket: {sid}')

# --- HTTPX client wrapper and lifespan ---

class HTTPXClientWrapper:
    async_client: httpx.AsyncClient = None

    def start(self):
        self.async_client = httpx.AsyncClient(timeout=300)

    async def stop(self):
        await self.async_client.aclose()
        self.async_client = None

    def __call__(self):
        assert self.async_client is not None
        return self.async_client

httpx_client_wrapper = HTTPXClientWrapper()

@asynccontextmanager
async def lifespan(app: FastAPI):
    httpx_client_wrapper.start()
    remote_agent_addresses = [CHAT_AGENT_SERVER_URL]#"http://localhost:10002/a2a/chat_agent"]
    await agent_manager.initialize_available_agents(remote_agent_addresses)
    yield
    await httpx_client_wrapper.stop()

app.router.lifespan_context = lifespan

# --- Compose into an ASGI app with Socket.IO "on top" ---
asgi_app = socketio.ASGIApp(sio, other_asgi_app=app)

# --- Main ---
if __name__ == '__main__':
    import uvicorn
    print(CHAT_AGENT_SERVER_URL)
    uvicorn.run("app:asgi_app", host="localhost", port=8080, reload=True)