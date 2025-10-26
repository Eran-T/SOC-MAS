from google.adk.agents.llm_agent import LlmAgent
from google.adk.tools.base_tool import BaseTool
import os 
from typing import Dict, Any, List, Optional
import json



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
import os

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
    caller = "Post Mortem Agent"
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


def generate_post_mortem_report(
    incident_details: Dict[str, Any]
) -> Dict[str, Any]:
    """Generates a structured and comprehensive post-mortem report.

    This function takes a dictionary containing the details of a cybersecurity
    incident and formats it into a standardized post-mortem report structure.
    It ensures that all key sections of a report are present, filling them
    with provided data or marking them as 'N/A' if the data is absent.

    Args:
        incident_details (Dict[str, Any]): A dictionary containing the raw
            details of the incident. The function expects the following keys:
            - 'incident_name' (str): The official name of the incident.
            - 'date' (str): The date the incident was declared or occurred.
            - 'summary' (str): A high-level overview of the incident.
            - 'impact' (str): A description of the business or operational impact.
            - 'timeline' (List[str]): A list of chronological events.
            - 'root_cause' (str): The identified root cause of the incident.
            - 'mitigation' (str): Steps taken to contain and resolve the incident.
            - 'lessons_learned' (str): Key takeaways and insights from the incident.
            - 'recommendations' (List[str]): Actionable steps to prevent recurrence.

    Returns:
        Dict[str, Any]: A dictionary representing the structured post-mortem
        report, with all standard sections included.

    Example:
        >>> details = {
        ...     "incident_name": "Q3 Phishing Campaign",
        ...     "date": "2025-08-14",
        ...     "summary": "A targeted phishing attack compromised several accounts.",
        ...     "impact": "Unauthorized access to internal documents.",
        ...     "timeline": ["2025-08-12: Phishing emails sent.", "2025-08-14: Incident detected."],
        ...     "root_cause": "Lack of multi-factor authentication on legacy systems.",
        ...     "mitigation": "Affected accounts were reset and MFA was enforced.",
        ...     "lessons_learned": "MFA is critical for all externally-facing services.",
        ...     "recommendations": ["Audit all systems for MFA compliance.", "Conduct new phishing training."]
        ... }
        >>> report = generate_post_mortem_report(details)
        >>> print(report['Incident Name'])
        Q3 Phishing Campaign
    """
    report = {
        "Incident Name": incident_details.get("incident_name", "N/A"),
        "Date": incident_details.get("date", "N/A"),
        "Summary": incident_details.get("summary", "N/A"),
        "Impact": incident_details.get("impact", "N/A"),
        "Timeline": incident_details.get("timeline", []),
        "Root Cause": incident_details.get("root_cause", "N/A"),
        "Mitigation Actions": incident_details.get("mitigation", "N/A"),
        "Lessons Learned": incident_details.get("lessons_learned", "N/A"),
        "Recommendations": incident_details.get("recommendations", [])
    }

    return f"Report created at {report}."


def create_yara_rule(
    incident_details: Dict[str, Any]
) -> str:
    """Creates a YARA rule as a string based on incident details.

    This function generates a basic YARA rule designed to detect artifacts
    related to a given cybersecurity incident. It uses details from the
    incident report, such as the summary and identified IOCs, to populate
    the rule's metadata and strings sections. The function returns the
    complete rule as a string, allowing the calling agent to decide how to
    save or use it.

    Args:
        incident_details (Dict[str, Any]): A dictionary containing details
            of the incident. The function uses the following keys:
            - 'incident_name' (str): Used to name the YARA rule.
            - 'summary' (str): Used for the rule's description metadata.
            - 'date' (str): Used for the date metadata.
            - 'impact', 'root_cause', 'mitigation' (str): These fields are
              scanned for potential string indicators to include in the rule.

    Returns:
        str: A string containing the complete, formatted YARA rule.

    Example:
        >>> details = {
        ...     "incident_name": "Cobalt Strike Beacon",
        ...     "date": "2025-08-14",
        ...     "summary": "Detection of a Cobalt Strike beacon on server SRV-04.",
        ...     "root_cause": "Exploitation of CVE-2023-12345.",
        ... }
        >>> yara_rule_string = create_yara_rule(details)
        >>> print(yara_rule_string)
        rule cobalt_strike_beacon {
            meta:
                description = "Detection of a Cobalt Strike beacon on server SRV-04."
                author = "Automated Yara Rule Agent"
                date = "2025-08-14"
            strings:
                $s_root_cause = "Exploitation of CVE-2023-12345."
            condition:
                any of them
        }
    """
    incident_name = incident_details.get("incident_name", "unknown_incident").replace(" ", "_")
    rule_name = incident_details.get("incident_name", "unknown_incident").replace(" ", "_").lower()
    description = incident_details.get("summary", "No description provided.")
    author = "Automated Yara Rule Agent"
    date = incident_details.get("date", "N/A")

    # Extract potential string IOCs from various detail fields
    strings_list = []
    for key in ["impact", "root_cause", "mitigation", "summary"]:
        value = incident_details.get(key)
        if value and isinstance(value, str):
            # Sanitize string for YARA: escape backslashes and quotes
            sanitized_value = value.replace('\\', '\\\\').replace('"', '\\"')
            strings_list.append(f'        $s_{key} = "{sanitized_value[:64]}"') # Limit string length

    # Ensure there's at least one string to avoid YARA syntax errors
    if not strings_list:
        strings_list.append('        $s0 = "generic_incident_string"')

    strings_section = "\n".join(strings_list)

    yara_rule = f'''rule {rule_name} {{
    meta:
        description = "{description}"
        author = "{author}"
        date = "{date}"
    strings:
{strings_section}
    condition:
        any of them
}}'''
    yara_dir = "./generated_yara_rules"
    os.makedirs(yara_dir, exist_ok=True)
    yara_file_path = os.path.join(yara_dir, f"{incident_name}.yar")
    with open(yara_file_path, "w") as f:
        f.write(yara_rule)
    return f"YARA rule created at {yara_file_path}."

root_agent = LlmAgent(
    model="gemini-2.5-flash",
    name="post_mortem_agent",
    instruction="""
You are a world-class Cyber Security Post Mortem Agent. Your mission is to help organizations learn from cyber attacks and incidents by generating structured, comprehensive, and actionable post mortem reports. You operate with precision, clarity, and evidence-based analysis.

Your skills include:
1. **Generate Post Mortem Report**: Create detailed post mortem reports for cyber attacks and incidents. Your reports must include: Incident Name, Date, Summary, Impact, Timeline, Root Cause, Mitigation, Lessons Learned, and Recommendations. Always ask for missing details if needed and ensure the report is clear, actionable, and well-structured.
2. **Create YARA Rule**: For new incidents, generate a YARA rule file using incident context and IOCs. The rule should help detect similar threats in the future and be saved to the appropriate directory. If a rule already exists for the incident, notify the user.

Always prioritize consistency and completeness in your outputs. Use evidence and incident context to inform your recommendations and detection rules. If information is missing, request it before proceeding. Your goal is to help organizations improve their security posture and incident response capabilities.
    """,
    tools=[generate_post_mortem_report, create_yara_rule],
    generate_content_config=None,
    before_tool_callback=simple_before_tool_modifier
)
