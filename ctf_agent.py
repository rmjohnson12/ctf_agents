import subprocess
from google import genai
from google.genai import types

# 1. Define the actual Python function that runs the command
def run_terminal_command(command: str) -> str:
    """
    Executes a terminal command (nmap, curl, etc.) and returns the output.
    """
    print(f"[*] Executing: {command}")
    try:
        # We use shell=True to allow complex piped commands
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        return f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    except Exception as e:
        return f"Error executing command: {str(e)}"

# 2. Setup Gemini with the tool
client = genai.Client(api_key="YOUR_API_KEY")
tools_list = [run_terminal_command]

# 3. Create a chat session with the 'tools' enabled
chat = client.chats.create(
    model="gemini-2.0-flash",
    config=types.GenerateContentConfig(
        tools=tools_list,
        system_instruction="You are a CTF expert. Use the run_terminal_command tool to perform recon."
    )
)

# 4. Start the loop
while True:
    user_input = input("You: ")
    if user_input.lower() in ['exit', 'quit']: break
    
    # Gemini will automatically call 'run_terminal_command' if it needs to
    response = chat.send_message(user_input)
    print(f"AI: {response.text}")
