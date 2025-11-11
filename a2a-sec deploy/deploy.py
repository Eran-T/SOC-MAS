
# RODO: check if for subagents custom classes are needed
import os
import sys
import json
import argparse
import importlib.util
import vertexai

from vertexai import agent_engines
from vertexai.preview import reasoning_engines
from vertexai.preview.reasoning_engines import A2aAgent
from vertexai.agent_engines import ModuleAgent
from vertexai.preview.reasoning_engines.templates.a2a import create_agent_card
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.a2a.executor.a2a_agent_executor import A2aAgentExecutor
from google.adk.sessions import VertexAiSessionService
from pathlib import Path
from dotenv import load_dotenv
from google.genai import types as genai_types 

from a2a.server.apps.rest.rest_adapter import RESTAdapter

env_path = Path(__file__).parent / '.env'
print(f"Loading .env from: {env_path}")
load_dotenv(dotenv_path=env_path)


from a2a.server.agent_execution.context import RequestContext
from typing import Any


##########################3#######################3#######################3#######################3


import uuid
import hashlib

class MyVertexAiSessionService(VertexAiSessionService):

    async def create_session(self, app_name, user_id, state={}, session_id=None):
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


#########################
from google.adk.a2a.executor.a2a_agent_executor import A2aAgentExecutorConfig
from google.adk.runners import RunConfig
from google.adk.a2a.converters.request_converter import AgentRunRequest
def _get_user_id_from_context(request: RequestContext) -> str:
  # Get user from call context if available (auth is enabled on a2a server)
  if (
      request._params
      and request._params.metadata
      and request._params.metadata.get('user_id')
  ):
    return request._params.metadata.get('user_id')
  return f'A2A_USER_{request.context_id}'

def my_convert_a2a_request_to_agent_run_request(
    request: RequestContext,
    part_converter
) -> AgentRunRequest:
  if not request.message:
    raise ValueError('Request message cannot be None')

  return AgentRunRequest(
      user_id=_get_user_id_from_context(request),
      session_id=request.context_id,
      new_message=genai_types.Content(
          role='user',
          parts=[part_converter(part) for part in request.message.parts],
      ),
      run_config=RunConfig(),
  )


def parse_env_vars(env_vars_str):
    """Converts the 'key1=val1,key2=val2' string into a dictionary."""
    if not env_vars_str:
        return {}  # Return an empty dict if input is None or empty
        
    env_dict = {}
    try:
        pairs = env_vars_str.split(',')
        for pair in pairs:
            # Split only on the first '=' in case value contains '='
            key, value = pair.split('=', 1) 
            env_dict[key.strip()] = value.strip()
        return env_dict
    except ValueError:
        print(f"⚠️  Warning: Could not parse env_vars string: {env_vars_str}")
        print("   Expected format: key1=val1,key2=val2")
        return {} # Return empty dict on error

def deploy_agent(agent_name: str, base_dir: str, env_vars_str):
    """
    Dynamically loads and deploys a specified agent from a given base directory.
    Prints the final resource name to stdout and logs to stderr.
    """
    print(f"🐍 Python Deployer: Starting deployment for agent '{agent_name}' from '{base_dir}'...", file=sys.stderr)
    
    # --- 1. Construct Paths ---
    agent_dir = os.path.join(base_dir, agent_name)
    agent_json_path = os.path.join(agent_dir, "agent.json")
    agent_py_path = os.path.join(agent_dir, "agent.py")

    if not os.path.isdir(agent_dir):
        print(f"❌ Error: Agent directory not found at '{agent_dir}'", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(agent_json_path) or not os.path.exists(agent_py_path):
        print(f"❌ Error: 'agent.json' or 'agent.py' not found in '{agent_dir}'", file=sys.stderr)
        sys.exit(1)
    environment_variables = parse_env_vars(env_vars_str)
    # --- 2. Load agent-specific configuration ---
    with open(agent_json_path, "r") as f:
        agent_card_dict = json.load(f)

    # --- 3. Dynamically import the agent's root_agent with its full module path ---
    try:
        # Construct the full module name based on the directory structure.
        # e.g., "agents.remote_agents.agent_1.agent"
        # This ensures cloudpickle records the correct dependency, matching your non-generic script.
        module_path_parts = os.path.normpath(base_dir).split(os.sep) + [agent_name, "agent"]
        module_name = ".".join(module_path_parts)
        print(f"   -> Dynamically importing module as: '{module_name}'", file=sys.stderr)

        spec = importlib.util.spec_from_file_location(module_name, agent_py_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not create module spec for {agent_py_path}")
        
        agent_module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = agent_module
        spec.loader.exec_module(agent_module) #####
        root_agent = agent_module.root_agent

        print(f"✅ Successfully imported 'root_agent' from {agent_py_path}", file=sys.stderr)

    except (AttributeError, ImportError) as e:
        print(f"❌ Error dynamically importing 'root_agent' from {agent_py_path}: {e}", file=sys.stderr)
        sys.exit(1)

    # --- 4. Prepare Environment Variables for the Remote Agent ---
    env_vars_to_pass = {}
    build_options = {}
    extra_packages = [agent_py_path]
    if agent_name == "chat_agent":
        for key, value in os.environ.items():
            if key.endswith("_AGENT_RESOURCE_NAME"):
                env_vars_to_pass[key] = value
                print(f"   -> Found and will pass env var: {key}", file=sys.stderr)
    
    
    
    else:
        if 'SERVICE_URL' in os.environ:
            env_vars_to_pass['SERVICE_URL'] = os.environ['SERVICE_URL']
            print(f"   -> Found and will pass env var: SERVICE_URL", file=sys.stderr)
                
    env_vars_to_pass.update(environment_variables)
    # --- 5. Set up Vertex AI ---
    agent_name_upper = agent_name.upper()
    staging_bucket_env_var = f"{agent_name_upper}_STAGING_BUCKET"
    default_bucket_name = f"agent-staging-{agent_name.replace('_', '-')}"
    GOOGLE_CLOUD_PROJECT = os.environ.get('GOOGLE_CLOUD_PROJECT')
    AGENT_STAGING_BUCKET = os.environ.get(staging_bucket_env_var, default_bucket_name)
    LOCATION = os.environ.get("REGION")
    FILE_HANDLER_SERVICE_ACCOUNT_NAME = os.environ.get("FILE_HANDLER_SERVICE_ACCOUNT_NAME")
    print(f"FILE_HANDLER_SERVICE_ACCOUNT_NAME: {FILE_HANDLER_SERVICE_ACCOUNT_NAME}", file=sys.stderr)
    CHAT_AGNET_SA = f"{FILE_HANDLER_SERVICE_ACCOUNT_NAME}@{GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
    if not GOOGLE_CLOUD_PROJECT:
        print("❌ Error: GOOGLE_CLOUD_PROJECT environment variable not set.", file=sys.stderr)
        sys.exit(1)
    print(f"[DEBUG]: ENV VARS: {env_vars_to_pass}", file=sys.stderr)
    print(f"🌍 Using Project: {GOOGLE_CLOUD_PROJECT}", file=sys.stderr)
    print(f"📦 Using Staging Bucket: gs://{AGENT_STAGING_BUCKET}", file=sys.stderr)
    
    vertexai.init(project=GOOGLE_CLOUD_PROJECT, staging_bucket=f"gs://{AGENT_STAGING_BUCKET}")

    # # --- 6. Build and Create the Agent Engine ---
    agent_card = create_agent_card(agent_card=agent_card_dict)
    runner = Runner(
        app_name=agent_name,
        agent=root_agent,
        session_service=VertexAiSessionService(project=GOOGLE_CLOUD_PROJECT, location=LOCATION),
    )
    a2a_agent = A2aAgent(
        agent_card=agent_card,
        agent_executor_builder=A2aAgentExecutor,
        agent_executor_kwargs={"runner": runner}
    )

    print("🛠️  Creating agent engine on Vertex AI... this may take a few minutes.", file=sys.stderr)

    remote_app = agent_engines.create(
        agent_engine=a2a_agent,
        display_name=agent_name,
        requirements=[
            "google-cloud-aiplatform[agent_engines,adk]>=1.112.0",
            "google-cloud-discoveryengine == 0.13.12",
            "a2a-sdk >= 0.3.4",
            "requests",
            "httpx",
            "google-adk == 1.17.0"

        ],
        env_vars=env_vars_to_pass,
        # Now that the local import creates the correct full module path, we can
        # pass just the agent.py file, just like in your working non-generic script.
        extra_packages=extra_packages,
        service_account=CHAT_AGNET_SA if agent_name == 'chat_agent' else None
    )

    # --- 7. Update Agent Engine With Resource Name ---
    resource_name = remote_app.resource_name
    agent_id = resource_name.split('/')[-1]

    runner = Runner(
        app_name=resource_name,
        agent=root_agent,
        session_service=MyVertexAiSessionService(project=GOOGLE_CLOUD_PROJECT, location=LOCATION, agent_engine_id=agent_id),
    )
    config = A2aAgentExecutorConfig(request_converter=my_convert_a2a_request_to_agent_run_request) if agent_name == "chat_agent" else A2aAgentExecutorConfig()
    a2a_agent = A2aAgent(
        agent_card=agent_card,
        agent_executor_builder=A2aAgentExecutor,
        agent_executor_kwargs={"runner": runner, "config":config}
    )
    
    remote_app = agent_engines.update(
        resource_name=resource_name,
        agent_engine=a2a_agent,
        env_vars=env_vars_to_pass
    )
    print("🛠️  Updating agent engine with resource name... this may take a few minutes.", file=sys.stderr)

    # --- 8. Final Output ---
    print("\n" + "="*50, file=sys.stderr)
    print(f"🎉 Successfully deployed agent: {agent_name}", file=sys.stderr)
    print(f"✅ Agent Engine Resource Name: {resource_name}", file=sys.stderr)
    print("="*50 + "\n", file=sys.stderr)

    # Print ONLY the resource name to stdout for the calling script to capture
    print(resource_name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Deploy a remote agent to Vertex AI Agent Engines."
    )
    parser.add_argument(
        "agent_name",
        type=str,
        help="The name of the agent to deploy (must match directory name)."
    )
    parser.add_argument(
        "base_dir",
        type=str,
        help="The base directory where the agent's folder is located (e.g., 'agents/remote_agents')."
    )
    parser.add_argument(
        "--env_vars",
        type=str,
        default=None,  # Value will be None if the flag is not provided
        help="A string of comma-separated key=value pairs for environment variables."
    )
    args = parser.parse_args()
    deploy_agent(args.agent_name, args.base_dir, args.env_vars)

