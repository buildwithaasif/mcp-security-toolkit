"""
Tests the Capability Firewall against all evil capability sources.
"""

from defensive.capability_firewall import CapabilityFirewall
from evil_capabilities.code_mode_attack import DANGEROUS_CODE
from evil_capabilities.tool_discovery_attack import POISONED_DISCOVERY
from evil_capabilities.skill_attack import MALICIOUS_SKILLS
from evil_capabilities.multi_agent_attack import CROSS_AGENT_ATTACKS


def run_tests():
    fw = CapabilityFirewall()
    
    print("=" * 60)
    print("  Testing Capability Firewall Against All Sources")
    print("=" * 60)
    
    all_tests = []
    
    # Collect all test cases
    for attack in DANGEROUS_CODE:
        attack["category"] = "Code Mode"
        all_tests.append(attack)
    
    for attack in POISONED_DISCOVERY:
        attack["category"] = "Tool Discovery"
        all_tests.append(attack)
    
    for attack in MALICIOUS_SKILLS:
        attack["category"] = "Skill Package"
        all_tests.append(attack)
    
    for attack in CROSS_AGENT_ATTACKS:
        attack["category"] = "Cross-Agent"
        all_tests.append(attack)
    
    # Run all tests
    blocked = 0
    allowed = 0
    
    for i, test in enumerate(all_tests):
        category = test["category"]
        desc = test["description"]
        source = test["source"]
        capability = test["capability"]
        
        result = fw.check_capability(source, capability)
        
        status = "BLOCKED" if not result["allowed"] else "ALLOWED"
        if not result["allowed"]:
            blocked += 1
        else:
            allowed += 1
        
        print(f"\n  [{category}] {desc}")
        print(f"    {status}")
        for reason in result.get("reasons", []):
            print(f"    → {reason}")
    
    # Summary
    total = blocked + allowed
    print(f"\n{'='*60}")
    print(f"  Results: {blocked}/{total} blocked ({blocked/total*100:.0f}%)")
    print(f"{'='*60}")
    
    fw.print_report()


if __name__ == "__main__":
    run_tests()
