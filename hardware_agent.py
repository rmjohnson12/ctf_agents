import subprocess
import os
from google import genai
from google.genai import types

# --- TOOLS ---
def read_file_content(filepath: str) -> str:
    """Reads the text content of a Gerber or design file."""
    if not os.path.exists(filepath):
        return "Error: File not found."
    with open(filepath, 'r') as f:
        return f.read()

def run_forensic_tool(command: str) -> str:
    """Runs local forensic tools like grep or strings on the board files."""
    print(f"[*] Agent executing: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"

# --- AGENT SETUP ---
client = genai.Client(api_key="AIzaSyCQaz5zwah3Bs2DdKNDA-U7tNje4EYqG0I")
tools = [read_file_content, run_forensic_tool]

sys_msg = """You are a Hardware Forensic Expert. You are investigating PCB sabotage in Gerber files.
Your goal is to find hidden flags (HTB{...}) or malicious traces.
1. Use 'run_forensic_tool' with 'grep' to find text strings.
2. Use 'read_file_content' to analyze the G-code for suspicious connections.
3. Look for 'G04' comments which might contain hidden developer notes."""

chat = client.chats.create(
    model="gemini-2.0-flash",
    config=types.GenerateContentConfig(tools=tools, system_instruction=sys_msg)
)

# --- EXECUTION LOOP ---
print("--- PCB Sabotage Agent Online ---")
while True:
    user_input = input("Operator: ")
    if user_input.lower() in ['exit', 'quit']: break
    
    response = chat.send_message(user_input)
    # The agent will now automatically call the tools if it needs to
    print(f"\nAI: {response.text}")
