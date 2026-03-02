from engine.dns_cell import run_dns_recon
from engine.network_cell import run_network_recon
from engine.web_cell import run_web_recon
from engine.attack_logic import generate_attack_vectors

def run_recon(target):
    print(f"\n========== INITIALIZING STATE-LEVEL RECON: {target} ==========")
    
    # Execute Cells
    dns_intel = run_dns_recon(target)
    network_intel = run_network_recon(target)
    web_intel = run_web_recon(target)
    
    # Feed intelligence to Attack Logic
    attack_intel = generate_attack_vectors(network_intel, web_intel)
    
    print(f"========== RECON COMPLETE ==========\n")
    
    # Package the final intelligence report
    return {
        "dns": dns_intel,
        "network": network_intel,
        "web": web_intel,
        "attack_vectors": attack_intel
    }