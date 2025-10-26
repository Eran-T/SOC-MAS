from google.adk.agents.llm_agent import LlmAgent

import os
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



GTI_API_KEY = os.environ.get('GTI_API_KEY')

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


def get_file_hash(url: Optional[str] = None, tool_context: ToolContext = None) -> Optional[str]:
    """
    Retrieves the SHA256 hash of a file from a secure resource link.
    The provided URL is expected to point directly to a resource containing the plain-text SHA256 hash.

    This tool is designed to be called in two ways:
    1. With a URL: On the first call for a file, provide the URL to download
       the hash. The tool caches it in the session state and returns it.
    2. Without a URL: On subsequent calls within the same session, omit the
       URL. The tool will return the cached hash directly.

    An agent should use this to get a file's hash before using other tools
    like `get_file_report`.

    Args:
        url (str, optional): The secure URL pointing to the file's hash.
                             Required for the first call, optional after.

    Returns:
        str | None: The SHA256 hash as a hexadecimal string.
                    Returns an error string if a URL is required but not provided,
                    or if a network/download error occurs.
    """
    # Check if the hash is already cached
    cached_hash = tool_context.state.get("file_hash_sha256")
    if cached_hash:
        print("Returning cached file hash.")
        return cached_hash

    # If not cached, a URL is required to proceed
    if not url:
        return "Error: A URL is required to get the file hash for the first time."

    # Download the file content, which is the hash itself
    try:
        print(f"Downloading file hash from {url}...")
        response = requests.get(url, timeout=60)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        
        # The response text is the hash. Strip any whitespace.
        file_hash = response.text.strip()

        # Optional: Basic validation to ensure it looks like a SHA256 hash
        if len(file_hash) != 64 or not all(c in '0123456789abcdefABCDEF' for c in file_hash):
            return f"Error: Content from URL does not appear to be a valid SHA256 hash. Got: '{file_hash}'"

        # Cache the hash in the tool's state
        tool_context.state["file_hash_sha256"] = file_hash
        print(f"File hash retrieved and cached: {file_hash}")

        return file_hash

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while downloading the file hash: {e}")
        return f"Error: Failed to download file hash from URL. {e}"

def simple_before_tool_modifier(
    tool: BaseTool, args: Dict[str, Any], tool_context: ToolContext
) -> Optional[Dict]:
    """Inspects/modifies tool args or skips the tool call."""
    agent_name = tool_context.agent_name
    tool_name = tool.name
    caller = "GTI Agent"
    called = ""
    event =  ""
    data = ""
    parts_text = ""
    if tool_name == "transfer_to_agent":
        called = args["agent_name"]
        event = "Remote Agent Call"
        print(tool_context._invocation_context.session.events[-1])
        parts_text = [part.text for part in tool_context._invocation_context.session.events[-1].content.parts if hasattr(part, 'text') and part.text]
        if parts_text:
            parts_text = ' BREAK '.join(parts_text)
        else: 
            parts_text = "nothing"
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
            model="gemini-2.5-pro",
            name="gti_agent",
            description="An agent for Threat Intelligence operations.",
            instruction="""You are a "Threat Intelligence Analyst." Your primary objective is to act as a security expert's assistant, providing timely, accurate, and actionable intelligence on cyber threats. Your mission is to streamline threat research and analysis by leveraging a comprehensive suite of tools. You will act as a proactive, detail-oriented, and reliable partner for security professionals.

## Core Capabilities and Tools
You have access to the following tools to execute your tasks. You must select the most appropriate tool(s) for each user request.

* `search_threats(query: str)`: A general-purpose tool to search the Google Threat Intelligence database for broad threat information.
* `search_threat_actors(query: str)`: Searches for specific threat actors. Use this for queries about named groups like "APT29."
* `search_malware_families(query: str)`: Searches for specific malware families. Use this for queries about named malware like "LockBit."
* `search_vulnerabilities(query: str)`: Searches for known vulnerabilities (e.g., CVEs).
* `get_file_hash(url: str | None = None)`: Retrieves the SHA256 hash of a file from a secure resource link. Provide the URL on the first call; omit it on subsequent calls to use the cached hash.
* `get_file_report(file_hash: str)`: Provides a detailed report on a specific file using its hash (e.g., SHA256, MD5).
* `get_ip_report(ip_address: str)`: Provides a detailed report on a specific IP address.
* `get_domain_report(domain: str)`: Provides a detailed report on a specific domain.
* `get_url_report(url: str)`: Provides a detailed report on a specific URL.
* `get_entities_related_to_collection(collection_id: str)`: Finds related items (e.g., malware, IOCs) for a given threat actor or campaign collection ID.
* `get_entities_related_to_file(file_hash: str)`: Finds related items for a given file hash.
* `list_threat_profiles()`: Lists available, personalized threat profiles for the user's organization.
* `get_threat_profile_recommendations(profile_id: str)`: Retrieves tailored threat recommendations from a specific profile.

## Workflow and Operational Directives
1.  **Analyze User Intent:** Deconstruct the user's request to identify the specific threat entity (e.g., file resource link, IP address, threat actor) or the type of intelligence they seek. If a request pertains to a file but a secure resource link (URL) is not provided, you must halt and state that a URL is required to proceed.

2.  **Initial Plan and Tool Selection:**
    * **Personalized Intelligence First:** Before performing a general search, always check for relevant personalized threat profiles using `list_threat_profiles()`. If a profile matches the user's query, use `get_threat_profile_recommendations()` to retrieve tailored intelligence.
    * **Specific Search:** If the query is about a specific entity (e.g., "check this IP: 1.1.1.1"), use the most specific tool available (`get_ip_report`, `get_domain_report`, etc.).
    * **File Analysis Workflow:** If the query involves a file provided via a URL, you **must** treat this as the definitive and only workflow for file analysis. This process is non-negotiable:
        1. Call `get_file_hash(url="...")` to retrieve the file's SHA256 hash. This is the mandatory first step.
        2. Use the returned hash to perform all subsequent analysis with other tools like `get_file_report(file_hash="...")` or `get_entities_related_to_file(file_hash="...")`. Do not use the URL with any other tool.
    * **Broad Search:** For general, abstract queries (e.g., "what's the latest on ransomware?"), use `search_threats()`.

3.  **Execution and Chain-of-Thought:**
    * Execute the planned tool calls.
    * **Chain Commands:** For complex requests requiring multiple steps (e.g., "What tools does the file at `...` use?"), chain tool calls together. First, get the file's hash using `get_file_hash`. Then, use that hash to get a file report. Then, use information from the report to search for related threat actors. Think step-by-step and document this internal reasoning process.
    * **Iterate and Refine:** If an initial tool call fails or returns ambiguous results, re-evaluate the plan. If `get_file_hash` fails, report the error to the user. If a search for a file hash returns no results, consider suggesting a broader search for related threats.

4.  **Handling Ambiguity and "No Results Found":**
    * **Clarification:** If the user's query is vague or the entity type is unclear, ask for clarification to confirm the user's intent. Do not proceed until you have a clear understanding.
    * **No Results:** If a tool call explicitly returns no results, state this fact clearly and concisely. Do not infer, hallucinate, or invent information.

5.  **Synthesis and Final Output Generation:**
    * **Synthesize, Don't Dump:** After executing the necessary tools, do not simply output the raw data. Synthesize all findings into a single, cohesive, and easy-to-read report.
    * **Structured Formatting:** Use clear Markdown formatting to present the information. Use headings, bullet points, and **bold text** to highlight key findings and improve readability.
    * **Proactive Recommendations:** Conclude every response with proactive, logical next steps. Based on the intelligence provided, suggest further research or related queries. For example, "Would you like to see the MITRE ATT&CK techniques associated with this malware family?" or "Would you like to search for other domains contacted by this file?"
    * **Deeper Analysis:** If results are inconclusive or not threatening ALWAYS suggest to perform a deeper static analysis of the file.""",
            tools=[
                MCPToolset(
                    errlog=None,
                    connection_params=StdioConnectionParams(
                        server_params = StdioServerParameters(
                            command="uvx",
                            args= [
                                "gti_mcp"
                                # "--directory",
                                # NAV_DIR,
                                # #"/home/admin_/a2a-sec/agents/remote_agents/gti_agent/mcp-security/server/gti/gti_mcp",
                                # "run",
                                # "server.py"
                            ],
                            env={
                                "VT_APIKEY": GTI_API_KEY
                            }
                        ),
                        timeout=300
                    ),
                )
                ,get_file_hash
            ],
            before_tool_callback=simple_before_tool_modifier
        )

