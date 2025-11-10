import vertexai

from vertexai import agent_engines
from vertexai.preview import reasoning_engines
import os 
from vertexai.preview.reasoning_engines import A2aAgent
from vertexai.agent_engines import ModuleAgent
import json
import sys

GOOGLE_CLOUD_PROJECT = os.environ.get('GOOGLE_CLOUD_PROJECT')
AGENT_STAGING_BUCKET = os.environ.get('GTI_AGENT_STAGING_BUCKET')
GTI_API_KEY = os.environ.get('GTI_API_KEY')
LOCATION=os.environ.get('REGION')
SERVICE_URL = os.environ.get('SERVICE_URL')
from agent import root_agent
vertexai.init(project=GOOGLE_CLOUD_PROJECT, staging_bucket=f"gs://{AGENT_STAGING_BUCKET}")

with open("agent.json", "r") as f:
    agent_card_dict = json.load(f)

from vertexai.preview.reasoning_engines.templates.a2a import create_agent_card
agent_card = create_agent_card(agent_card=agent_card_dict)

from google.adk.runners import Runner
from google.adk.sessions import VertexAiSessionService

class MyVertexAiSessionService(VertexAiSessionService):

    async def create_session(self, app_name, user_id, state={}, session_id=None):
        # if not session_id.isdigit():
        #     session_id=user_id.reaplace("A2A_USER_", "")
        #     print(f"❌❌❌❌❌❌❌ modified session_id in create_session: {session_id}",  file=sys.stderr)
        print(f"❌❌❌❌❌❌❌ create_session agent: {app_name} modified session_id: {session_id}",  file=sys.stderr)
        session = await super().create_session(
            app_name=app_name,
            user_id=user_id,
            state=state,
        )
        return session

    async def get_session(self, app_name, user_id, session_id):
        # Return None if session non exists.
        print(f"❌❌❌❌❌❌❌ get_session agent: {app_name} session_id: {session_id},",  file=sys.stderr)
        try:
            session = await super().get_session(
                app_name=app_name,
                user_id=user_id,
                session_id=session_id,
            )
            return session
        except Exception as e:
            print(f"❌❌❌❌❌❌❌ exception in : {e},",  file=sys.stderr)
            return None

# runner = Runner(
#     app_name="gti_agent",
#     agent=root_agent,
#     session_service=VertexAiSessionService(project=GOOGLE_CLOUD_PROJECT, location=LOCATION),
# )

from google.adk.a2a.executor.a2a_agent_executor import A2aAgentExecutor
from vertexai.preview.reasoning_engines import A2aAgent
a2a_agent = A2aAgent(
    agent_card=agent_card,
    agent_executor_builder=A2aAgentExecutor,
    agent_executor_kwargs={"runner": runner}
)


remote_app = agent_engines.create(
    agent_engine=a2a_agent,
    display_name='gti_agent',
    requirements=[
        "google-cloud-aiplatform[agent_engines,adk]>=1.112.0",
        "google-cloud-discoveryengine",
        "a2a-sdk >= 0.3.4",
        "requests",
        "httpx"
    ],
    env_vars = {
         "GTI_API_KEY": GTI_API_KEY,
    },
    extra_packages=["agent.py", "installation_scripts/install.sh"],
    build_options={
        "installation": [
            "installation_scripts/install.sh",
        ],
    },
)

# update the agent engine with the resource name

resource_name = remote_app.resource_name

agent_id = resource_name.split('/')[-1]
runner = Runner(
        app_name=resource_name,
        agent=root_agent,
        session_service=MyVertexAiSessionService(project=GOOGLE_CLOUD_PROJECT, location=LOCATION, agent_engine_id=agent_id),
    )
a2a_agent = A2aAgent(
    agent_card=agent_card,
    agent_executor_builder=A2aAgentExecutor,
    agent_executor_kwargs={"runner": runner}
)

remote_app = agent_engines.update(
    resource_name=resource_name,
    agent_engine=a2a_agent,
    requirements=[
        "google-cloud-aiplatform[agent_engines,adk]>=1.112.0",
        "google-cloud-discoveryengine",
        "a2a-sdk >= 0.3.4",
        "requests",
        "httpx"
    ],
    env_vars = {
         "GTI_API_KEY": GTI_API_KEY,
         "SERVICE_URL": SERVICE_URL
    },
    extra_packages=["agent.py", "installation_scripts/install.sh"],
    build_options={
        "installation": [
            "installation_scripts/install.sh",
        ],
    },
)


