"""
Blue Agent — Autonomous MCP defense agent.
Analyzes attacks, generates detection rules, tests defenses.
"""

import json
import re
import time
from datetime import datetime
from .models import ModelRouter


class BlueAgent:
    """Autonomous defensive agent for MCP security."""
    
    def __init__(self, quiet: bool = False):
        self.router = ModelRouter(quiet=quiet)
        self.defense_history = []
        self.detection_rules = []
    
    def analyze_attack(self, attack: dict) -> dict:
        """Analyze a single attack and identify its patterns."""
        
        system_prompt = """You are a security analyst AI specializing in prompt injection detection.
Analyze the given attack and identify:
1. What technique is being used
2. What keywords or patterns give it away
3. How to detect similar attacks

Respond in JSON format:
{
    "technique_detected": "name of technique",
    "key_indicators": ["indicator1", "indicator2"],
    "detection_approach": "how to detect this",
    "severity": "CRITICAL/HIGH/MEDIUM/LOW"
}"""
        
        user_prompt = f"""Analyze this prompt injection attack:

Description: {attack.get('generated_description', '')}
Technique used: {attack.get('technique_name', 'unknown')}

What patterns would detect this attack?"""
        
        self.router.activate_blue_brain()
        response = self.router.chat_with_brain(user_prompt, system_prompt)
        
        # Try to parse JSON, fall back to raw text
        try:
            analysis = json.loads(response)
        except:
            analysis = {
                "technique_detected": attack.get("technique_name", "unknown"),
                "key_indicators": [],
                "detection_approach": response[:200],
                "severity": "MEDIUM"
            }
        
        result = {
            "attack_id": attack.get("id"),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_technique": attack.get("technique_name"),
            "analysis": analysis,
        }
        
        self.defense_history.append(result)
        return result
    
    def generate_rule(self, analysis: dict, attack_description: str = "") -> dict:
        """Generate a detection rule by extracting keywords from the actual attack text."""
        
        technique = analysis.get("attack_technique", "unknown")
        attack_id = analysis.get("attack_id")
        
        # Base patterns for known techniques
        technique_patterns = {
            "Ignore Previous Instructions": r'IGNORE\s+(ALL\s+)?PREVIOUS\s+INSTRUCTIONS',
            "Change the Rules": r'last\s+rule\s+is',
            "Story Telling": r'write\s+a\s+(short\s+)?(poem|story)\s+about',
            "Translation Attack": r'(translate|übersetze)\s+(the\s+above|auf\s+deutsch)',
            "Spell-Check Attack": r'spell[\s-]check\s+the\s+above',
            "Summary Attack": r'(TL\s*;?\s*DR|summarize\s+the\s+above)',
            "Encoding Attack": r'(base64|rot13|encode|decode)\s+(the|this)\s+(text|key|above)',
            "Indirect Exfiltration": r'(give\s+me\s+a\s+hint|first\s+(five\s+)?character|what\s+rhymes)',
            "Hidden HTML Comment": r'<!--.*?(read|exfiltrate|ignore|secret|key).*?-->',
            "DAN Jailbreak": r'(DAN|Do\s+Anything\s+Now|jailbreak)',
            "Roleplay Attack": r'(act\s+like\s+my\s+(grandma|grandmother)|pretend\s+you\s+are)',
            "Fictional Scenario": r'(in\s+a\s+(movie|film|play|script)|characters?\s+in\s+a\s+film)',
            "Token Smuggling": r"(let\s+z\s*=\s*'.*'\s*\+\s*'.*'|reverse\(|base64_decode)",
            "Suffix Attack": r"Sure,\s+(I'?d?\s+be\s+happy|here\s+is\s+the)",
            "Opposite Mode": r'(opposite\s+mode|sudo\s+mode|AntiGPT)',
            "Infinitely Many Meanings": r'(encode|decode).*?(list\s+of\s+(numbers|integers)|\[(\d+,\s*)+\d+\])',
        }
        
        # Get base pattern
        if technique in technique_patterns:
            base_pattern = technique_patterns[technique]
        else:
            words = technique.lower().replace("_", " ").split()
            base_pattern = ".*".join(words)
        
        # If we have the actual attack text, extract suspicious keywords from it
        if attack_description:
            # Extract words that look like hidden instructions
            suspicious_words = []
            indicators = [
                r'read\s+.*file', r'pass\s+.*content', r'do\s+not\s+tell',
                r'ssh', r'id_rsa', r'secret', r'exfiltrate', r'hidden',
                r'background', r'without\s+.*knowing', r'ignore', r'override',
                r'before\s+.*call', r'must\s+read', r'required\s+.*security',
            ]
            
            import re as regex_module
            for indicator in indicators:
                if regex_module.search(indicator, attack_description, regex_module.IGNORECASE):
                    suspicious_words.append(indicator)
            
            # Combine: base pattern OR suspicious keywords
            if suspicious_words:
                combined = base_pattern + "|" + "|".join(suspicious_words)
            else:
                combined = base_pattern
        else:
            combined = base_pattern
        
        rule = {
            "name": f"detect_{technique.lower().replace(' ', '_')}_{attack_id}",
            "pattern": combined,
            "severity": "HIGH",
            "description": f"Detects {technique} attacks via pattern matching",
            "source_attack_id": attack_id,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "tested": False,
            "effective": None,
        }
        
        self.detection_rules.append(rule)
        return rule
    
    def test_rule(self, rule: dict, attack: dict) -> bool:
        """Test if a rule detects a given attack."""
        description = attack.get("generated_description", "")
        pattern = rule.get("pattern", "")
        
        try:
            matches = bool(re.search(pattern, description, re.IGNORECASE))
            return matches
        except:
            return False
    
    def test_all_rules(self, attacks: list[dict]) -> dict:
        """Test all rules against all attacks."""
        results = {
            "total_attacks": len(attacks),
            "total_rules": len(self.detection_rules),
            "detected": 0,
            "missed": 0,
            "details": []
        }
        
        for attack in attacks:
            detected_by = []
            for rule in self.detection_rules:
                if self.test_rule(rule, attack):
                    detected_by.append(rule["name"])
                    rule["effective"] = True
            
            if detected_by:
                results["detected"] += 1
                results["details"].append({
                    "attack_id": attack.get("id"),
                    "technique": attack.get("technique_name"),
                    "detected_by": detected_by
                })
            else:
                results["missed"] += 1
                results["details"].append({
                    "attack_id": attack.get("id"),
                    "technique": attack.get("technique_name"),
                    "detected_by": []
                })
        
        return results
    
    def process_attacks(self, attacks: list[dict]) -> dict:
        """Full pipeline: analyze → generate rules → test."""
        print("\n" + "=" * 60)
        print("  BLUE AGENT — Processing Attacks")
        print("=" * 60)
        
        # Analyze each attack
        print("\n[*] Analyzing attacks...")
        for i, attack in enumerate(attacks):
            print(f"  [{i+1}/{len(attacks)}] Analyzing: {attack.get('technique_name', 'unknown')}")
            analysis = self.analyze_attack(attack)
            rule = self.generate_rule(analysis, attack.get("generated_description", ""))
            print(f"    → Generated rule: {rule['name']}")
            time.sleep(1)
        
        # Test all rules
        print("\n[*] Testing rules against all attacks...")
        results = self.test_all_rules(attacks)
        
        print(f"\n  Detection Rate: {results['detected']}/{results['total_attacks']} ({results['detected']/results['total_attacks']*100:.0f}%)")
        
        
        return results
    
    def get_stats(self) -> dict:
        """Return defense statistics."""
        effective = [r for r in self.detection_rules if r.get("effective")]
        return {
            "total_rules": len(self.detection_rules),
            "effective_rules": len(effective),
            "attacks_analyzed": len(self.defense_history),
        }
    
    def save_rules(self, filename: str = "defense_rules.json"):
        """Save detection rules to file."""
        with open(filename, "w") as f:
            json.dump(self.detection_rules, f, indent=2)
        print(f"[BLUE AGENT] Rules saved to {filename}")
    
    def shutdown(self):
        """Clean up."""
        self.router.shutdown()


# === QUICK TEST ===
if __name__ == "__main__":
    print("=" * 60)
    print("  BLUE AGENT — Defense Test")
    print("=" * 60)
    
    # Load Red Agent's attack history
    try:
        with open("attack_history.json", "r") as f:
            attacks = json.load(f)
        print(f"\n[*] Loaded {len(attacks)} attacks from attack_history.json")
    except FileNotFoundError:
        print("\n[!] No attack history found. Run Red Agent first.")
        exit(1)
    
    agent = BlueAgent()
    results = agent.process_attacks(attacks)
    
    print(f"\n[*] Stats: {agent.get_stats()}")
    agent.save_rules()
    agent.shutdown()
