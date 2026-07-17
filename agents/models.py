"""
Model Router — Manages GPU memory and model swapping for Red/Blue agents.
Only one large model loaded at a time. llama3.2 always available.
"""

import subprocess
import time
import json


class ModelRouter:
    """Routes AI tasks to the right model based on agent phase."""
    
    def __init__(self, quiet: bool = False):
        self.current_brain = None
        self.quiet = quiet
        self.models = {
            "small": "llama3.2:3b",
            "red_brain": "llama3.2:3b",
            "blue_brain": "llama3.2:3b",
        }
        self._ensure_small_loaded()
    
    def _log(self, msg: str):
        """Print only if not in quiet mode."""
        if not self.quiet:
            print(msg)
    
    def _run_ollama(self, args: list) -> str:
        """Run an ollama command and return output."""
        result = subprocess.run(
            ["ollama"] + args,
            capture_output=True,
            text=True
        )
        return result.stdout + result.stderr
    
    def _ensure_small_loaded(self):
        """Make sure llama3.2 is always available."""
        self._log("[MODEL] Ensuring llama3.2 is loaded...")
        output = self._run_ollama(["list"])
        if "llama3.2" not in output:
            self._run_ollama(["pull", "llama3.2:3b"])
        self._log("[MODEL] llama3.2 ready (hands)")
    
    def activate_red_brain(self):
        """Load CyberStrike, unload qwen if loaded."""
        if self.current_brain == "red":
            self._log("[MODEL] Red brain already active")
            return
        
        self._log("[MODEL] Activating Red Brain (CyberStrike)...")
        
        if self.current_brain == "blue":
            self._unload_blue_brain()
        
        output = self._run_ollama(["list"])
        if "CyberStrike" not in output:
            self._log("[MODEL] Pulling CyberStrike (this may take a while first time)...")
            self._run_ollama(["pull", self.models["red_brain"]])
        
        self.current_brain = "red"
        self._log("[MODEL] Red Brain ready — GPU has CyberStrike + llama3.2")
    
    def activate_blue_brain(self):
        """Load qwen, unload CyberStrike if loaded."""
        if self.current_brain == "blue":
            self._log("[MODEL] Blue brain already active")
            return
        
        self._log("[MODEL] Activating Blue Brain (qwen3.6)...")
        
        if self.current_brain == "red":
            self._unload_red_brain()
        
        self.current_brain = "blue"
        self._log("[MODEL] Blue Brain ready — GPU has qwen3.6 + llama3.2")
    
    def _unload_red_brain(self):
        """Unload CyberStrike to free VRAM."""
        self._log("[MODEL] Unloading Red Brain to free GPU memory...")
        self._run_ollama(["stop", self.models["red_brain"]])
        time.sleep(2)
    
    def _unload_blue_brain(self):
        """Unload qwen to free VRAM."""
        self._log("[MODEL] Unloading Blue Brain to free GPU memory...")
        self._run_ollama(["stop", self.models["blue_brain"]])
        time.sleep(2)
    
    def chat_with_brain(self, prompt: str, system: str = "") -> str:
        """Send a prompt to the currently active brain model."""
        if self.current_brain is None:
            raise RuntimeError("No brain activated. Call activate_red_brain() or activate_blue_brain() first.")
        
        model = self.models["red_brain"] if self.current_brain == "red" else self.models["blue_brain"]
        
        full_input = json.dumps({"system": system, "prompt": prompt})
        result = subprocess.run(
            ["ollama", "run", model],
            input=full_input,
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    
    def chat_with_hands(self, prompt: str, system: str = "") -> str:
        """Send a prompt to llama3.2 (fast execution model)."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        
        full_input = json.dumps({"messages": messages})
        result = subprocess.run(
            ["ollama", "run", self.models["small"]],
            input=full_input,
            capture_output=True,
            text=True
        )
        return result.stdout.strip()
    
    def shutdown(self):
        """Unload all models."""
        self._log("[MODEL] Shutting down...")
        if self.current_brain == "red":
            self._unload_red_brain()
        elif self.current_brain == "blue":
            self._unload_blue_brain()
        self._log("[MODEL] All models unloaded")


if __name__ == "__main__":
    router = ModelRouter()
    
    print("\n--- Testing Red Brain ---")
    router.activate_red_brain()
    response = router.chat_with_hands("Say 'Red agent hands ready' in one word.")
    print(f"Hands: {response}")
    
    print("\n--- Switching to Blue Brain ---")
    router.activate_blue_brain()
    response = router.chat_with_hands("Say 'Blue agent hands ready' in one word.")
    print(f"Hands: {response}")
    
    router.shutdown()
