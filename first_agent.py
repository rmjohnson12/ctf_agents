from google import genai
import os

# 1. Setup the Client
# Replace 'YOUR_API_KEY' with the key you got from AI Studio
client = genai.Client(api_key="AIzaSyCQaz5zwah3Bs2DdKNDA-U7tNje4EYqG0I")

# 2. Define the Agent's Persona
sys_instruct = "You are a CTF expert. Analyze the following tool output and suggest the next exploit command."

# 3. Simple Interaction Loop
def analyze_scan(scan_results):
    response = client.models.generate_content(
        model="gemini-2.0-flash", # Or "gemini-1.5-pro" for deeper logic
        config={'system_instruction': sys_instruct},
        contents=f"Nmap results: {scan_results}"
    )
    return response.text

# Example usage:
nmap_output = "Port 80: Apache 2.4.41 open. Port 22: OpenSSH 8.2p1 open."
print(analyze_scan(nmap_output))
