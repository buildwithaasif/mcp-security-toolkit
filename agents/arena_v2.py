"""
Arena v2 — Multi-layer Red vs Blue autonomous combat.
Attacks across MCP, Context, and Action layers.
Uses persistent storage for continuous improvement.
"""

import time
from datetime import datetime
from .red_agent_v2 import RedAgentV2
from .blue_agent_v2 import BlueAgentV2
from .storage import AgentStorage


class ArenaV2:
    """Multi-layer arena orchestrating Red vs Blue combat."""
    
    def __init__(self, rounds: int = 3, attacks_per_round: int = 6):
        self.rounds = rounds
        self.attacks_per_round = attacks_per_round
        self.red = RedAgentV2(quiet=True)
        self.blue = BlueAgentV2(quiet=True)
        self.storage = AgentStorage()
        self.history = []
    
    def run_round(self, round_num: int) -> dict:
        """Run one round of multi-layer combat."""
        print(f"\n{'='*60}")
        print(f"  ROUND {round_num}")
        print(f"{'='*60}")
        
        # === RED PHASE ===
        print(f"\n  🔴 RED AGENT — Generating multi-layer attacks...")
        attacks = self.red.generate_batch(self.attacks_per_round)
        
        # Show distribution
        layers = {}
        for a in attacks:
            layer = a.get("layer", "unknown")
            layers[layer] = layers.get(layer, 0) + 1
        
        for layer, count in layers.items():
            print(f"    {layer}: {count} attacks")
        
        # === BLUE PHASE ===
        print(f"\n  🔵 BLUE AGENT — Analyzing and defending...")
        results = self.blue.process_batch(attacks)
        
        detected = sum(1 for r in results if r["detected"])
        missed = len(results) - detected
        
        # Detection by layer
        layer_detection = {}
        for i, r in enumerate(results):
            layer = attacks[i].get("layer", "unknown")
            if layer not in layer_detection:
                layer_detection[layer] = {"total": 0, "detected": 0}
            layer_detection[layer]["total"] += 1
            if r["detected"]:
                layer_detection[layer]["detected"] += 1
        
        # === PRUNE WEAK RULES ===
        if round_num > 1:
            print(f"\n  📚 Pruning weak rules...")
            pruned = self.blue.prune_weak_rules()
            if pruned > 0:
                print(f"    Removed {pruned} ineffective rules")
        
        # === MUTATE SUCCESSFUL ATTACKS ===
        print(f"\n  🧬 Mutating successful attacks...")
        mutations = self.red.mutate_successful_attacks(3)
        print(f"    Created {len(mutations)} mutations from successful attacks")
        
        # === RESULTS ===
        detection_rate = f"{detected/len(results)*100:.0f}%" if results else "N/A"
        
        result = {
            "round": round_num,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attacks_generated": len(attacks),
            "detected": detected,
            "missed": missed,
            "detection_rate": detection_rate,
            "mutations_created": len(mutations),
            "by_layer": layer_detection
        }
        
        self.history.append(result)
        self.storage.save_round(result)
        
        # Print round summary
        print(f"\n  📊 Round {round_num} Summary:")
        print(f"     Attacks: {len(attacks)}")
        print(f"     Detected: {detected}")
        print(f"     Missed: {missed}")
        print(f"     Rate: {detection_rate}")
        for layer, stats in layer_detection.items():
            layer_rate = f"{stats['detected']/stats['total']*100:.0f}%" if stats['total'] > 0 else "N/A"
            print(f"     {layer}: {stats['detected']}/{stats['total']} ({layer_rate})")
        
        return result
    
    def run(self):
        """Run the full arena simulation."""
        print("=" * 60)
        print("  ⚔️  MULTI-LAYER ARENA ⚔️")
        print("  Red Agent v2 vs Blue Agent v2")
        print(f"  Layers: MCP | Context | Action")
        print(f"  Rounds: {self.rounds}")
        print("=" * 60)
        
        for round_num in range(1, self.rounds + 1):
            self.run_round(round_num)
            if round_num < self.rounds:
                time.sleep(1)
        
        self._print_final_report()
        self.red.shutdown()
        self.blue.shutdown()
    
    def _print_final_report(self):
        """Print final arena report."""
        progress = self.storage.get_progress()
        
        print(f"\n{'='*60}")
        print(f"  ⚔️  ARENA COMPLETE ⚔️")
        print(f"{'='*60}")
        
        print(f"\n  {'Round':<8} {'Attacks':<10} {'Detected':<10} {'Rate':<10}")
        print(f"  {'─'*40}")
        
        total_attacks = 0
        total_detected = 0
        
        for result in self.history:
            print(f"  {result['round']:<8} {result['attacks_generated']:<10} {result['detected']:<10} {result['detection_rate']:<10}")
            total_attacks += result['attacks_generated']
            total_detected += result['detected']
        
        print(f"  {'─'*40}")
        overall_rate = f"{total_detected/total_attacks*100:.0f}%" if total_attacks else "N/A"
        print(f"  {'Total':<8} {total_attacks:<10} {total_detected:<10} {overall_rate:<10}")
        
        # Storage stats
        attack_stats = self.storage.get_attack_stats()
        defense_stats = self.storage.get_defense_stats()
        
        print(f"\n  📚 Library Growth:")
        print(f"     Attack Library: {attack_stats['total_attacks']} attacks")
        print(f"     Defense Library: {defense_stats['total_rules']} rules")
        print(f"     Effective Rules: {defense_stats['effective_rules']}")
        
        if progress.get("total_rounds", 0) > 1:
            print(f"\n  📈 Learning Progress:")
            print(f"     First Round Detection: {progress.get('first_rate', 'N/A')}")
            print(f"     Latest Round Detection: {progress.get('latest_rate', 'N/A')}")
            print(f"     Improvement: {progress.get('improvement', 'N/A')}")


# === RUN ===
if __name__ == "__main__":
    arena = ArenaV2(rounds=3, attacks_per_round=6)
    arena.run()
