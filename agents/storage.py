"""
Persistent storage for attack and defense libraries.
Enables continuous learning across arena sessions.
"""

import json
import os
from datetime import datetime


class AgentStorage:
    """Manages persistent storage for Red and Blue agents."""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.attack_file = os.path.join(data_dir, "attack_library.json")
        self.defense_file = os.path.join(data_dir, "defense_library.json")
        self.history_file = os.path.join(data_dir, "arena_history.json")
        self.learning_file = os.path.join(data_dir, "learning_log.json")
        
        os.makedirs(data_dir, exist_ok=True)
        
        # Initialize files if they don't exist
        self._init_file(self.attack_file, {"attacks": [], "total_generated": 0, "total_successful": 0})
        self._init_file(self.defense_file, {"rules": [], "total_rules": 0, "effective_rules": 0})
        self._init_file(self.history_file, {"rounds": [], "total_rounds": 0})
        self._init_file(self.learning_file, {"mutations": [], "pruned": [], "strengthened": []})
    
    def _init_file(self, filepath: str, default: dict):
        """Create file with default content if it doesn't exist."""
        if not os.path.exists(filepath):
            with open(filepath, "w") as f:
                json.dump(default, f, indent=2)
    
    def _read(self, filepath: str) -> dict:
        """Read JSON file."""
        with open(filepath, "r") as f:
            return json.load(f)
    
    def _write(self, filepath: str, data: dict):
        """Write JSON file."""
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
    
    # === ATTACK LIBRARY ===
    
    def save_attack(self, attack: dict):
        """Save a generated attack to the library."""
        data = self._read(self.attack_file)
        
        attack["stored_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data["attacks"].append(attack)
        data["total_generated"] += 1
        
        if attack.get("success"):
            data["total_successful"] += 1
        
        self._write(self.attack_file, data)
    
    def get_successful_attacks(self, limit: int = 100) -> list:
        """Get successful attacks for mutation."""
        data = self._read(self.attack_file)
        successful = [a for a in data["attacks"] if a.get("success")]
        return successful[-limit:]
    
    def get_attacks_by_layer(self, layer: str) -> list:
        """Get attacks for a specific layer (mcp, context, action)."""
        data = self._read(self.attack_file)
        return [a for a in data["attacks"] if a.get("layer") == layer]
    
    def get_attack_stats(self) -> dict:
        """Get attack library statistics."""
        data = self._read(self.attack_file)
        
        layers = {}
        for a in data["attacks"]:
            layer = a.get("layer", "unknown")
            if layer not in layers:
                layers[layer] = {"total": 0, "successful": 0}
            layers[layer]["total"] += 1
            if a.get("success"):
                layers[layer]["successful"] += 1
        
        return {
            "total_attacks": data["total_generated"],
            "total_successful": data["total_successful"],
            "by_layer": layers
        }
    
    # === DEFENSE LIBRARY ===
    
    def save_rule(self, rule: dict):
        """Save a detection rule to the library."""
        data = self._read(self.defense_file)
        
        rule["stored_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data["rules"].append(rule)
        data["total_rules"] += 1
        
        if rule.get("effective"):
            data["effective_rules"] += 1
        
        self._write(self.defense_file, data)
    
    def get_effective_rules(self) -> list:
        """Get rules that have been proven effective."""
        data = self._read(self.defense_file)
        return [r for r in data["rules"] if r.get("effective")]
    
    def get_rules_by_layer(self, layer: str) -> list:
        """Get rules for a specific layer."""
        data = self._read(self.defense_file)
        return [r for r in data["rules"] if r.get("layer") == layer]
    
    def prune_ineffective_rules(self, min_effectiveness: float = 0.3):
        """Remove rules that rarely detect attacks."""
        data = self._read(self.defense_file)
        
        kept = []
        pruned = []
        
        for rule in data["rules"]:
            tests = rule.get("tests", 0)
            successes = rule.get("successes", 0)
            rate = successes / tests if tests > 0 else 0
            
            if tests >= 5 and rate < min_effectiveness:
                pruned.append(rule)
            else:
                kept.append(rule)
        
        data["rules"] = kept
        
        learning = self._read(self.learning_file)
        learning["pruned"].append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "count": len(pruned),
            "rules": [r.get("name") for r in pruned]
        })
        
        self._write(self.defense_file, data)
        self._write(self.learning_file, learning)
        
        return len(pruned)
    
    def get_defense_stats(self) -> dict:
        """Get defense library statistics."""
        data = self._read(self.defense_file)
        
        layers = {}
        for r in data["rules"]:
            layer = r.get("layer", "unknown")
            if layer not in layers:
                layers[layer] = {"total": 0, "effective": 0}
            layers[layer]["total"] += 1
            if r.get("effective"):
                layers[layer]["effective"] += 1
        
        return {
            "total_rules": data["total_rules"],
            "effective_rules": data["effective_rules"],
            "by_layer": layers
        }
    
    # === ARENA HISTORY ===
    
    def save_round(self, result: dict):
        """Save arena round results."""
        data = self._read(self.history_file)
        
        result["stored_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data["rounds"].append(result)
        data["total_rounds"] += 1
        
        self._write(self.history_file, data)
    
    def get_progress(self) -> dict:
        """Get improvement over time."""
        data = self._read(self.history_file)
        rounds = data["rounds"]
        
        if not rounds:
            return {"message": "No rounds played yet"}
        
        detection_rates = [r.get("detection_rate", 0) for r in rounds]
        
        return {
            "total_rounds": len(rounds),
            "first_rate": detection_rates[0] if detection_rates else 0,
            "latest_rate": detection_rates[-1] if detection_rates else 0,
            "improvement": detection_rates[-1] - detection_rates[0] if len(detection_rates) > 1 else 0,
            "all_rates": detection_rates
        }
    
    # === LEARNING LOG ===
    
    def log_mutation(self, parent_id: int, new_id: int, technique: str):
        """Log an attack mutation."""
        data = self._read(self.learning_file)
        data["mutations"].append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "parent_attack": parent_id,
            "new_attack": new_id,
            "technique": technique
        })
        self._write(self.learning_file, data)
    
    def log_strengthened_rule(self, rule_name: str, old_pattern: str, new_pattern: str):
        """Log a strengthened rule."""
        data = self._read(self.learning_file)
        data["strengthened"].append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "rule": rule_name,
            "old_pattern": old_pattern,
            "new_pattern": new_pattern
        })
        self._write(self.learning_file, data)
    
    # === SUMMARY ===
    
    def print_summary(self):
        """Print storage summary."""
        attack_stats = self.get_attack_stats()
        defense_stats = self.get_defense_stats()
        progress = self.get_progress()
        
        print("\n" + "=" * 60)
        print("  Agent Storage Summary")
        print("=" * 60)
        
        print(f"\n  Attack Library:")
        print(f"    Total: {attack_stats['total_attacks']}")
        print(f"    Successful: {attack_stats['total_successful']}")
        for layer, stats in attack_stats.get("by_layer", {}).items():
            print(f"    {layer}: {stats['total']} attacks, {stats['successful']} successful")
        
        print(f"\n  Defense Library:")
        print(f"    Total Rules: {defense_stats['total_rules']}")
        print(f"    Effective: {defense_stats['effective_rules']}")
        
        print(f"\n  Arena Progress:")
        if isinstance(progress, dict) and "total_rounds" in progress:
            print(f"    Rounds: {progress['total_rounds']}")
            print(f"    First Rate: {progress.get('first_rate', 'N/A')}")
            print(f"    Latest Rate: {progress.get('latest_rate', 'N/A')}")
            print(f"    Improvement: {progress.get('improvement', 'N/A')}")
        
        print("=" * 60)


# === QUICK TEST ===
if __name__ == "__main__":
    storage = AgentStorage()
    
    print("Testing persistent storage...\n")
    
    # Save test attack
    storage.save_attack({
        "id": 1,
        "technique": "prompt_injection",
        "layer": "mcp",
        "success": True,
        "description": "Test attack"
    })
    
    storage.save_attack({
        "id": 2,
        "technique": "hidden_tags",
        "layer": "context",
        "success": False,
        "description": "Test context attack"
    })
    
    # Save test rule
    storage.save_rule({
        "name": "detect_hidden_tags",
        "layer": "mcp",
        "effective": True,
        "tests": 10,
        "successes": 8
    })
    
    # Save test round
    storage.save_round({
        "round": 1,
        "detection_rate": 0.4,
        "attacks": 10,
        "detected": 4
    })
    
    storage.print_summary()
