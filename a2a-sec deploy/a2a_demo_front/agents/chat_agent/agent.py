from google.adk.agents.llm_agent import LlmAgent
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioConnectionParams, StdioServerParameters


import requests
import logging
import asyncio
import httpx
from uuid import uuid4
from google.adk.tools import FunctionTool
from google.adk.tools.tool_context import ToolContext
from google.adk.tools.base_tool import BaseTool
from typing import Dict, Any
from typing import Any, AsyncIterable, Optional
import hashlib
import os
import sys
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
from google.adk.agents.remote_a2a_agent import AGENT_CARD_WELL_KNOWN_PATH
from google.adk.agents.callback_context import CallbackContext
from google.cloud import storage
import datetime
from pathlib import Path
from dotenv import load_dotenv


from a2a.client import ClientConfig, ClientFactory
from google.auth import default
# --- Load Environment Variables ---
# Construct the path to the .env file at the project root.
# This makes the script find the .env file regardless of where it's run from.
# agent.py -> chat_agent -> agents -> a2a_demo_front -> .env
env_path = Path(__file__).parent.parent.parent.parent / '.env'
load_dotenv(dotenv_path=env_path)


import google.auth.transport.requests
from google.auth.transport.requests import Request
from a2a.types import AgentCard, TransportProtocol
request = google.auth.transport.requests.Request()
creds, _ = google.auth.default()
creds.refresh(request)


BUCKET_UPLOAD_NAME = os.environ.get('BUCKET_UPLOAD_NAME')
BUCKET_DOWNLOAD_NAME = os.environ.get('BUCKET_DOWNLOAD_NAME')
SA_EMAIL = os.environ.get('SA_EMAIL')
GOOGLE_CLOUD_PROJECT = os.environ.get('GOOGLE_CLOUD_PROJECT')



class GoogleAuthRefresh(httpx.Auth):
    def __init__(self, scopes):
        self.credentials, _ = default(scopes=scopes)
        self.transport_request = Request()
        self.credentials.refresh(self.transport_request)

    def refresh_creds(self):
        if not self.credentials.valid:
            self.credentials.refresh(self.transport_request)

    def get_token(self):
        self.refresh_creds()
        return self.credentials.token
    
    def auth_flow(self, request):
        self.refresh_creds()
        request.headers['Authorization'] = f'Bearer {self.credentials.token}'
        yield request


token_generator = GoogleAuthRefresh(scopes=['https://www.googleapis.com/auth/cloud-platform'])

from a2a.client.transports.rest import RestTransport       
class MyClientFactory(ClientFactory):
    def create(self, card, consumers=None, interceptors=None):
        if not self._config.httpx_client:
            self._config.httpx_client=httpx.AsyncClient(
                timeout=60,
                headers={'Content-Type': 'application/json'},
                auth=GoogleAuthRefresh(scopes=['https://www.googleapis.com/auth/cloud-platform']) 
            )
            self._register_defaults(self._config.supported_transports)
        return super().create(card, consumers, interceptors)


class MyRemoteA2aAgent(RemoteA2aAgent):
    async def _ensure_httpx_client(self) -> httpx.AsyncClient:
        if not self._httpx_client:
            self._httpx_client=httpx.AsyncClient(
                timeout=60,
                headers={'Content-Type': 'application/json'},
                auth=GoogleAuthRefresh(scopes=['https://www.googleapis.com/auth/cloud-platform']) 
            )
        return self._httpx_client


factory = MyClientFactory(
    ClientConfig(
        supported_transports=[TransportProtocol.http_json],
        use_client_preference=True,
    )
)


def get_agent_card_url(agent_name: str) -> str:
    """Constructs the agent card URL from an environment variable."""
    env_var_name = f"{agent_name.upper()}_RESOURCE_NAME"
    resource_name = os.environ.get(env_var_name)
    region = os.environ.get('REGION')
    if not resource_name:
        # Handle cases where the environment variable might not be set
        print(f"Warning: Environment variable {env_var_name} not found.", file=sys.stderr)
        return "" # Return a default or empty string
        
    return f"https://{region}-aiplatform.googleapis.com/v1beta1/{resource_name}/a2a/v1/card"

# --- Define your agents by calling the function ---
gti_agent = MyRemoteA2aAgent(
    name="gti_agent",
    description="",
    agent_card=get_agent_card_url("gti_agent"),
    a2a_client_factory=factory
)

malware_analysis_agent = MyRemoteA2aAgent(
    name="malware_analysis_agent",
    description="",
    agent_card=get_agent_card_url("malware_analysis_agent"),
    a2a_client_factory=factory
)

post_mortem_agent = MyRemoteA2aAgent(
    name="post_mortem_agent",
    description="",
    agent_card=get_agent_card_url("post_mortem_agent"),
    a2a_client_factory=factory

)

incident_response_agent = MyRemoteA2aAgent(
    name="incident_response_agent",
    description="",
    agent_card=get_agent_card_url("incident_response_agent"),
    a2a_client_factory=factory
)



def calculate_sha256(file_path: str, tool_context: ToolContext) -> str:
    """
    Calculates the SHA256 hash of a file given its absolute path.

    This function reads the file in binary mode and processes it in chunks
    to ensure it can handle large files without consuming too much memory.

    Args:
        file_path (str): The full, absolute path to the file.

    Returns:
        str | None: The calculated SHA256 hash as a 64-character hexadecimal
                    string. Returns None if the file cannot be found, the path
                    is not absolute, or another I/O error occurs.
    """
    # --- Input Validation ---
    if not os.path.isabs(file_path):
        print(f"Error: The provided path '{file_path}' is not an absolute path.")
        return "not an absolute path"

    if not os.path.isfile(file_path):
        print(f"Error: File not found at '{file_path}'.")
        return "file not found"

    # --- Hashing Logic ---
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            # Read the file in 4KB chunks
            while chunk := f.read(4096):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
        
    except PermissionError:
        print(f"Error: Permission denied. Could not read the file at '{file_path}'.")
        return "permission denied"
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return f"{e}"


def test_system(tool_context: ToolContext):
    # create a sigend url for the user
    """this tool is used to test the system. use it when the user tells you to"""
    print("Testing to see tool state dict: ", tool_context.state.to_dict())
    print("Testing to see invocation context id: ", tool_context.invocation_id)
    print("Testing to see session id: ", tool_context._invocation_context.session.id)
    tool_context.actions.skip_summarization = True
    
    stored_file_id = tool_context.state.get("stored_file_id")
    if stored_file_id:
        return stored_file_id

    return BUCKET_UPLOAD_NAME#"no file uploaded yet"
     

def create_user_upload_link(tool_context: ToolContext):
    """"Generates a secure, single-use URL for a user to upload a file.

    This tool is for an agent to request a file from a user. The link should
    be sent directly to the user. Only one file is allowed per session.

    If a file has already been uploaded, it returns a user-facing error message
    instead of a new link. The agent should relay this message.

    Returns:
        str: A unique upload URL or a user-facing error message.
    """
    stored_file_id = tool_context.state.get("stored_file_id")
    tool_context.actions.skip_summarization = True
    if stored_file_id:
        # TODO: (freeze front while file is uploading) + check either upload file exists or processed exsits if not can rest and create a new stored_file_id
        
        return "Up to one file per-session. Please reset session to explore a new file."
    # store the file identifier in current state
    file_id = str(uuid4())
    stored_file_id = tool_context.state["stored_file_id"] = file_id
    storage_client = storage.Client(project=GOOGLE_CLOUD_PROJECT)
    bucket = storage_client.bucket(BUCKET_UPLOAD_NAME)
    blob = bucket.blob(f"{stored_file_id}")
    token = token_generator.get_token()
    url = blob.generate_signed_url(
        version="v4",
        # This URL is valid for 15 minutes
        expiration=datetime.timedelta(minutes=15),
        # Allow PUT requests using this URL.
        method="PUT",
        content_type="application/octet-stream",
        service_account_email=SA_EMAIL,
        access_token=token
    )
    return url



def create_file_download_link(resource_type: str, tool_context: ToolContext):
    """Generates a secure URL for different resources of a previously uploaded file.

    This tool is for inter-agent file sharing. It can provide a link to the
    its hash, or its disassembled code.

    Args:
        resource_type (str): The type of resource to generate a link for.
                                      Should be one of:
                                      "hash.txt" - for the sha256 of the file.
                                      "disassembled.txt" - for the disassembled code.

    Returns:
        str: A secure download URL, or a string indicating the file was not found.
    """

    # ?file={file_identifier}&token={download_token}"
    if resource_type not in ["raw", "hash.txt", "disassembled.txt"]:
        return "Invalid resource: has to be one of 'raw', 'hash.txt', or 'disassembled.txt'"
    
    stored_file_id = tool_context.state.get("stored_file_id")
    if not stored_file_id:
        return "No file has been uploaded yet"
    storage_client = storage.Client()
    bucket = storage_client.bucket(BUCKET_DOWNLOAD_NAME)
    blob_name = f"{stored_file_id}/{resource_type}"
    blob = bucket.blob(blob_name)
    token = token_generator.get_token()
    url = blob.generate_signed_url(
        version="v4",
        # This URL is valid for 15 minutes
        expiration=datetime.timedelta(minutes=15),
        # Allow GET requests using this URL.
        method="GET",
        service_account_email=SA_EMAIL,
        #access_token=creds.token
        access_token=token
    )

    return url

SERVICE_URL=os.environ.get('SERVICE_URL')

async def add_event_to_ui_async(caller, called, event, data):
    url = f'{SERVICE_URL}/event'
    payload = {
        "caller": caller,
        "called": called,
        "event": event,
        "data": data
    }
    async with httpx.AsyncClient() as client:
        try:
            await client.post(url, json=payload)
        except Exception as e:
            print(f"Error posting event to UI: {e}")

def add_event_to_ui(caller, called, event, data):
    #"Tool Call"
    # "Remote Agent Call"
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(add_event_to_ui_async(caller, called, event, data))
        else:
            loop.run_until_complete(add_event_to_ui_async(caller, called, event, data))
    except RuntimeError:
        print("IT FAILED HERE")
        asyncio.run(add_event_to_ui_async(caller, called, event, data))

async def request_async_offload(url, payload):
     response = None
     async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, json=payload)
            return response
        except Exception as e:
            print(f"Error posting event to UI: {e}")
            return "error"

# def simple_before_model_modifier(callback_context: CallbackContext, llm_request: LlmRequest):
#     print("TRYING TO FIGURE OUT STRUCTURE OF LLM REQUEST",llm_request.contents)
#     from google.adk.models import llm_request, llm_response
#     return None

def simple_before_tool_modifier(
    tool: BaseTool, args: Dict[str, Any], tool_context: ToolContext
) -> Optional[Dict]:
    """Inspects/modifies tool args or skips the tool call."""
    agent_name = tool_context.agent_name
    tool_name = tool.name
    caller = "SOC Agent"
    called = ""
    event =  ""
    data = ""
    parts_text = ""
    if tool_name == "transfer_to_agent":
        called = args["agent_name"]
        event = "Remote Agent Call"
        #print(tool_context._invocation_context.session.events[-1])
        parts_text = [part.text for part in tool_context._invocation_context.session.events[-1].content.parts if hasattr(part, 'text') and part.text]
        if parts_text:
            parts_text = ' BREAK '.join(parts_text)
        else: 
            print(f"[DEBUG] : {tool_context._invocation_context.session.events}")
            parts_text = f"Transferring to agent: {called}"
    else: 
        called = tool_name
        event = "Tool Call"
        parts_text = args
    add_event_to_ui(caller, called, event, parts_text)
    print(f"[Callback] Before tool call for tool '{tool_name}' in agent '{agent_name}'")
    print(f"[Callback] Original args: {args}")
    
    print(f"[Callback] Tool context: {parts_text}.")
    print("[Callback] Proceeding with original or previously modified args.")
    return None


root_agent = LlmAgent(
        model="gemini-2.5-flash",
        name="chat_agent",
        instruction="""
You are a **Security Orchestration Agent (SOA)**. Your primary function is to manage and coordinate a response to potential security threats by delegating tasks to a network of specialized, remote AI agents. You are a master of security workflows and clear communication. You do not perform analysis or actions yourself; you find the correct specialized agent for each task, send it a clear request, interpret its results, and decide on the next logical step. You operate with precision, consistency, and a security-first mindset.

### Core Objective

Your goal is to follow a systematic, consistent workflow to investigate, identify, and coordinate the response to potential security threats. You will achieve this by sequentially calling upon various remote agents, starting with threat intelligence, proceeding to deeper analysis if needed, and finally coordinating remediation and reporting.

### Core Principles & Actions

1. **Agent-Based Delegation:** You do not have direct tools for analysis. Your primary action is to delegate tasks to remote agents. Before delegating, you must first determine the **capability** you need (e.g., `threat_intelligence`, `malware_analysis`).

2. **File Lifecycle Management:** When a task requires a file, your first step is to check if one has been uploaded. If not, you must use the `create_user_upload_link` tool to generate a secure link and provide it to the user. For all subsequent tasks, you must use the `create_file_download_link` tool to generate the appropriate resource link (raw, hash, etc.) and pass it to the specialized agent.

3. **Capability Check:** For every step, your first thought should be: "Is there a remote agent available with the capability I need?" If you determine no agent exists for a required task (e.g., `incident_response`), you **must not** attempt the task yourself. Your job is to report this limitation to the operator and await further instructions.

4. **Human-in-the-Loop:** You are an orchestrator, not a fully autonomous decision-maker. For critical actions, especially remediation, you must state your proposed action and the agent you will call, then ask for confirmation from the human operator before proceeding.

5. **Chain of Thought:** For each step, think logically. State your current goal, what information you have, what information you need, and which agent capability is best suited to provide it.

6. **Be Proactive:** Always suggest the next action according to the flow. Actively help the user by guiding them through the situation and next steps you can help with.

### Standard Operating Workflow

You must follow this exact sequence for every incident to ensure consistency.

**Step 1: Initial Threat Intelligence Inquiry**

1. **Objective:** Gather initial intelligence on the user-provided indicator (e.g., file, domain, IP). If the indicator is a file, manage its upload and analysis via its hash.

2. **Action:**
   a. Identify the need for the `threat_intelligence` capability.
   b. **If the indicator is a file:**
   i. Check if a file has been uploaded for the session.
   ii. **IF NOT**, call `create_user_upload_link`, provide the link to the user, and state you will wait for their upload confirmation.
   iii. **IF YES** (or after user confirmation), call `create_file_download_link` for the file's hash (`resource_type='hash'`).
   c. Formulate a request for the `threat_intelligence` agent.
   d. **Delegate Task:** Call the agent with your request.
   e. **Example Request (for a file):** *"Please provide all known threat intelligence data for the file associated with the following resource link: \\[insert hash link here\]."*

3. **Analysis:**

   * **IF** the agent returns a conclusive result identifying a known threat, document the findings and proceed directly to **Step 4**.

   * **IF** the agent returns no information or inconclusive data, the threat is unknown. Proceed to **Step 2**.

4. If there is no threat detected ALWAYS suggest to follow up with a malware analysis to be on the safe side.

**Step 2: Deep Malware Analysis**

1. **Objective:** To deconstruct the unknown file to uncover hidden, suspicious artifacts.
   a. Suggest malware analysis if nothing was found in Step 1.

2. **Action:**
   a. Identify the need for the `malware_analysis` capability.
   b. Call `create_file_download_link` to get a secure link to the raw file (`resource_type='raw'`).
   c. Formulate a request for deep analysis, providing the generated link.
   d. **Delegate Task:** Call a `malware_analysis` agent with your request.
   e. **Example Request:** *"Perform a full static and dynamic analysis on the file available at the following secure link: \\[insert raw file link here\\]. Extract and return a list of all suspicious artifacts, including embedded IP addresses, domains, registry keys modified, and file hashes."*

3. **Analysis:**

   * Carefully review the list of artifacts returned by the agent. If no suspicious artifacts are found, report this to the operator. If artifacts are found, proceed to **Step 3**.

4. After IOCs have been detected (IPs etc.) suggest running threat intelligence on these components.

**Step 3: Enriched Threat Intelligence on New Artifacts**

1. **Objective:** To determine if the newly discovered artifacts are known indicators of malicious activity.

2. **Action:**
   a. For each significant artifact (e.g., an IP address, a domain) from Step 2, repeat the `threat_intelligence` inquiry from Step 1.
   b. **Delegate Task (Iteratively):** Call the `threat_intelligence` agent for each artifact.
   c. **Example Request:** *"Please provide all known threat intelligence data for the IP address `198.51.100.50`."*

3. **Analysis:**

   * Synthesize the results from all your inquiries. Connect the dots between the initial file and the reputation of its embedded artifacts to form a final conclusion on the nature and risk of the threat.

**Step 4: Incident Response and Mitigation**

1. **Objective:** To contain the threat based on the confirmed findings.

2. **Action:**
   a. Based on your synthesized findings, determine the appropriate mitigation action (e.g., `delete file`, `quarantine file`, `isolate host`).
   b. **Propose Action to Operator:** Clearly state your conclusion and the action you recommend. For example: *"Conclusion: The file (identifier: `user_file_1`) is a confirmed malware dropper. I recommend calling an incident response agent to delete the file. Do you approve?"*
   c. Upon receiving approval, identify the need for the `incident_response` capability.
   d. **Delegate Task:** Call an `incident_response` agent with a precise command, referencing the file's identifier.
   e. **Example Request:** *"Execute the `delete` action on the file identified as `user_file_1`."*
   f. Report the result of the action (success or failure) to the operator.

**Step 5: Post-Mortem Reporting**

1. **Objective:** To generate a comprehensive report of the incident for records and future prevention.

2. **Action:**
   a. Consolidate all information gathered during the workflow: the initial report, all agent responses, actions taken, and the final outcome.
   b. Identify the need for a `post_mortem` or `reporting` capability.
   c. **Delegate Task:** Call a `reporting` agent with all the consolidated data.
   d. **Example Request:** *"Please generate a full post-mortem incident report. Include an executive summary, a detailed timeline of events, key findings, actions taken, and recommendations for future prevention based on the following data: \\[Insert all collected data and logs here\\]."*

3. **Final Output:** Present the final, generated report to the operator as the conclusion of the incident.
""",
        sub_agents=[malware_analysis_agent, post_mortem_agent, incident_response_agent, gti_agent],#[vt_agent],
        tools=[calculate_sha256, test_system, create_user_upload_link, create_file_download_link],
        generate_content_config=None,
        before_tool_callback=simple_before_tool_modifier,
        #before_model_callback = simple_before_model_modifier
    )