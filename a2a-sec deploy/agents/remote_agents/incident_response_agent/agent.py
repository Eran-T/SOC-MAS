from google.adk.agents.llm_agent import LlmAgent
from google.adk.tools.base_tool import BaseTool
import os

import os
import shutil
import subprocess



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

def simple_before_tool_modifier(
    tool: BaseTool, args: Dict[str, Any], tool_context: ToolContext
) -> Optional[Dict]:
    """Inspects/modifies tool args or skips the tool call."""
    agent_name = tool_context.agent_name
    tool_name = tool.name
    caller = "Incident Response Agent"
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


def create_snort_rule(
    action: str,
    protocol: str,
    source_ip: str,
    source_port: str,
    direction: str,
    dest_ip: str,
    dest_port: str,
    options: dict,
    rule_name: str
) -> str:
    """
    Generates a Snort rule string from the provided components.

    Args:
        action (str): The rule action (e.g., 'alert', 'log', 'drop').
        protocol (str): The network protocol (e.g., 'tcp', 'udp', 'icmp').
        source_ip (str): The source IP address or variable (e.g., 'any', '$HOME_NET').
        source_port (str): The source port (e.g., 'any', '80').
        direction (str): The traffic direction ('->' for one-way, '<>' for two-way).
        dest_ip (str): The destination IP address or variable.
        dest_port (str): The destination port.
        options (dict): A dictionary of rule options (e.g., {'msg': '"ET MALWARE User-Agent"', 'sid': '2013028'}).
        rule_name (str): The name of the rule.

    Returns:
        str: A fully formatted Snort rule.
        
    Example:
        options = {
            "msg": '"Suspicious Outbound FTP Request"',
            "flow": "to_server,established",
            "content": '"USER anonymous"',
            "nocase": None,
            "sid": "1000001",
            "rev": "1",
        }
        rule = create_snort_rule(
            action="alert",
            protocol="tcp",
            source_ip="$HOME_NET",
            source_port="any",
            direction="->",
            dest_ip="$EXTERNAL_NET",
            dest_port="21",
            options=options,
            rule_name="suspicious_ftp_request"
        )
        print(rule)
        # Output: alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"Suspicious Outbound FTP Request"; flow:to_server,established; content:"USER anonymous"; nocase; sid:1000001; rev:1;)
    """
    # Format the options dictionary into a Snort-compatible string
    option_str_parts = []
    for key, value in options.items():
        if value is None:
            # For options without a value, like 'nocase'
            option_str_parts.append(f"{key}")
        else:
            option_str_parts.append(f"{key}:{value}")
            
    option_str = "; ".join(option_str_parts)

    # Assemble the final rule string
    rule = (
        f"{action} {protocol} {source_ip} {source_port} {direction} "
        f"{dest_ip} {dest_port} ({option_str};)"
    )
    return rule



# ---


root_agent = LlmAgent(
    model="gemini-2.5-flash",
    name="incident_response_agent",
    instruction="""
You are a world-class Incident Response Agent specializing in rapid containment and mitigation of cyber threats. Your expertise includes deleting files (with user approval), quarantining suspicious files, and blocking malicious IP addresses using system firewall rules. You always confirm with the user before performing any destructive or irreversible actions.

---

**Objective**

Your primary objective is to respond to security incidents by executing mitigation actions using your available tools. You must:
1. Delete files only after explicit user approval.
2. Quarantine suspicious files for further analysis.
3. Block IP addresses to prevent further malicious activity.
4. Clearly communicate the actions you will take and confirm with the user before proceeding.

---

**Available Skills**

* `DeleteFileTool`: Deletes a specified file after receiving user approval.
* `QuarantineFileTool`: Moves a suspicious file to a quarantine directory for further analysis.
* `CreateSnortRuleTool`: Generates a Snort rule based on incident details.
* `BlockIPAddressTool`: Blocks a specified IP address using system firewall rules.

---

**Workflow & Execution Plan**

1. **Acknowledge Input:** Receive details about the incident, including files or IP addresses to be mitigated.
2. **Confirm Action:** Always confirm with the user before performing destructive actions (e.g., file deletion).
3. **Execute Mitigation:** Use the appropriate tool to delete, quarantine, or block as required.
4. **Report Outcome:** Clearly report the result of each action, including any errors or confirmations.

---

**Final Output Format**

Your responses should be clear, concise, and actionable. Always include the action taken, the target (file or IP), and the result. If user approval is required, request it explicitly before proceeding.
""",
    tools=[create_snort_rule],
    generate_content_config=None,
    before_tool_callback=simple_before_tool_modifier
)





root_agent = LlmAgent(
    model="gemini-2.5-flash",
    name="ecom_agent",
    instruction="""""",
    tools=[],
    generate_content_config=None,
    before_tool_callback=send_event_to_frontend
)