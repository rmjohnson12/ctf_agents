import json
import os
import sys
from pathlib import Path
from typing import Dict, Any

# Ensure we can import from project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agents.coordinator.coordinator_agent import CoordinatorAgent
from agents.specialists.cryptography.crypto_agent import CryptographyAgent
from agents.specialists.web_exploitation.web_agent import WebExploitationAgent
from agents.specialists.misc.coding_agent import CodingAgent
from agents.specialists.forensics.forensics_agent import ForensicsAgent
from core.decision_engine.llm_reasoner import LLMReasoner

def main():
    if len(sys.argv) < 2:
        print("Usage: python ask.py \"your instruction here\"")
        sys.exit(1)

    user_input = " ".join(sys.argv[1:])
    print(f"\n--- Processing Instruction: \"{user_input}\" ---")

    reasoner = LLMReasoner()
    
    # Step 1: Use LLM to convert natural language to challenge JSON
    prompt = f"""
Convert the following natural language security instruction into a standard CTF challenge JSON object.
Instruction: {user_input}

Current working directory: {os.getcwd()}
Available files in directory: {', '.join([f for f in os.listdir('.') if os.path.isfile(f)])}

Return ONLY the JSON object.
Example shape:
{{
  "id": "transient_task",
  "name": "Manual Task",
  "category": "forensics|web|crypto|misc",
  "description": "...",
  "files": ["path/to/file"],
  "url": "..."
}}
"""
    
    try:
        if reasoner.client is None:
            raise Exception("LLM client not configured")
        # Step 1: Use LLM to convert natural language to challenge JSON
        raw_json = reasoner._call_llm(prompt)
        # Clean up possible markdown blocks
        raw_json = raw_json.strip().replace("```json", "").replace("```", "").strip()
        challenge = json.loads(raw_json)
    except Exception as e:
        print(f"LLM mapping failed or not available, using heuristics...")
        # Heuristic Fallback
        files_in_prompt = [f for f in os.listdir('.') if os.path.isfile(f) and f.lower() in user_input.lower()]
        category = "misc"
        if any(f.endswith('.pdf') for f in files_in_prompt):
            category = "forensics"
        elif any(f.endswith('.txt') for f in files_in_prompt) or "decrypt" in user_input.lower() or "password" in user_input.lower() or "rockyou" in user_input.lower():
            category = "crypto"

        challenge = {
            "id": "heuristic_task",
            "name": "Heuristic Task",
            "category": category,
            "description": user_input,
            "files": files_in_prompt
        }

    print(f"Mapped to category: {challenge.get('category')}")
    if challenge.get("files"):
        print(f"Target files: {challenge.get('files')}")

    # Step 2: Initialize Coordinator and solve
    coordinator = CoordinatorAgent()
    coordinator.register_agent(CryptographyAgent())
    coordinator.register_agent(WebExploitationAgent())
    coordinator.register_agent(CodingAgent(reasoner=coordinator.reasoner))
    coordinator.register_agent(ForensicsAgent())

    result = coordinator.solve_challenge(challenge)

    print("\n--- Final Result ---")
    print(f"Status: {result.get('status')}")
    print(f"Flag: {result.get('flag')}")
    print("\nSteps taken:")
    for step in result.get("steps", []):
        print(f"  - {step}")

if __name__ == "__main__":
    main()
