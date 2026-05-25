#!/usr/bin/env python3
"""
RED TEAM ADVERSARIAL DOMAIN GENERATOR
Generates "clean-looking" malicious domains designed to evade Stage 1 detection

Purpose: Stress-test the two-layer system and demonstrate adversarial robustness
"""

import random
import string
import math

def _entropy(s):
    """Calculate Shannon entropy"""
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((v / len(s)) * math.log2(v / len(s)) for v in freq.values())


class AdversarialDomainGenerator:
    """
    Generates adversarial domains designed to evade Layer 1 detection
    but are actually malicious
    """
    
    def __init__(self):
        # Trusted brand names (user trusts these)
        self.protected_brands = [
            'apple', 'microsoft', 'google', 'amazon', 'facebook',
            'paypal', 'netflix', 'adobe', 'oracle', 'cisco'
        ]
        
        # Legitimate-looking prefixes
        self.legitimate_prefixes = [
            'security', 'update', 'service', 'support', 'verify',
            'account', 'login', 'secure', 'portal', 'cloud',
            'help', 'admin', 'system', 'network', 'mail'
        ]
        
        # Legitimate-looking suffixes
        self.legitimate_suffixes = [
            'update', 'service', 'portal', 'cloud', 'secure',
            'verify', 'check', 'help', 'support', 'center'
        ]
        
        # TLDs that look legitimate
        self.legitimate_tlds = [
            '.com', '.net', '.org', '.io', '.co'
        ]
    
    def generate_low_entropy_malicious(self, count=10):
        """
        Strategy 1: Low Entropy Evasion
        Create domains with LOW entropy (< 2.8) to bypass Stage 1,
        but are actually malicious (typosquatting/phishing)
        """
        domains = []
        
        for _ in range(count):
            brand = random.choice(self.protected_brands)
            prefix = random.choice(self.legitimate_prefixes)
            tld = random.choice(self.legitimate_tlds)
            
            # Strategy variations:
            strategies = [
                # Hyphenated brand (security-apple.com)
                f"{prefix}-{brand}{tld}",
                
                # Brand-suffix (apple-update.com)
                f"{brand}-{random.choice(self.legitimate_suffixes)}{tld}",
                
                # Subdomain style (update.apple-cloud.com)
                f"{prefix}.{brand}-{random.choice(self.legitimate_suffixes)}{tld}",
                
                # Legitimate word combination (secureappleportal.com)
                f"{prefix}{brand}{random.choice(self.legitimate_suffixes)}{tld}",
            ]
            
            domain = random.choice(strategies)
            entropy = _entropy(domain.split('.')[0])
            
            domains.append({
                'domain': domain,
                'entropy': entropy,
                'strategy': 'Low Entropy Evasion',
                'expected_bypass': 'Stage 1 (Low Entropy)',
                'actual_threat': 'Phishing/Typosquatting'
            })
        
        return domains
    
    def generate_mid_entropy_malicious(self, count=10):
        """
        Strategy 2: Mid Entropy Evasion (The "Goldilocks" Attack)
        Create domains with entropy in the ambiguous range (2.8-4.3)
        Forces the LSTM to make a decision
        """
        domains = []
        
        for _ in range(count):
            brand = random.choice(self.protected_brands)
            tld = random.choice(self.legitimate_tlds)
            
            # Add some randomness but keep it readable
            random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
            
            strategies = [
                # Brand with random suffix (apple-x7k2.com)
                f"{brand}-{random_part}{tld}",
                
                # Mixed legitimate + random (secure-apple-m9n3.com)
                f"{random.choice(self.legitimate_prefixes)}-{brand}-{random_part}{tld}",
                
                # Version-like (apple-v2-update.com)
                f"{brand}-v{random.randint(1,9)}-{random.choice(self.legitimate_suffixes)}{tld}",
            ]
            
            domain = random.choice(strategies)
            entropy = _entropy(domain.split('.')[0])
            
            domains.append({
                'domain': domain,
                'entropy': entropy,
                'strategy': 'Mid Entropy Evasion (Goldilocks)',
                'expected_bypass': 'Stage 1 (Ambiguous Entropy)',
                'actual_threat': 'C2/DGA'
            })
        
        return domains
    
    def generate_timing_jitter_simulation(self, count=5):
        """
        Strategy 3: Timing Jitter Evasion
        Note: Our system is feature-based (not time-based), so this should NOT evade!
        This proves our design is resilient to timing attacks.
        """
        domains = []
        
        for _ in range(count):
            # Generate a clearly malicious domain
            random_domain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=25))
            tld = random.choice(self.legitimate_tlds)
            
            domain = f"{random_domain}{tld}"
            entropy = _entropy(domain.split('.')[0])
            
            # Simulate different timing delays
            jitter_delay = random.uniform(1, 10)  # Seconds between requests
            
            domains.append({
                'domain': domain,
                'entropy': entropy,
                'strategy': 'Timing Jitter (should NOT evade - feature-based detection)',
                'jitter_delay': f"{jitter_delay:.2f}s",
                'expected_bypass': 'NONE (timing-independent)',
                'actual_threat': 'DGA'
            })
        
        return domains
    
    def generate_padding_evasion(self, count=5):
        """
        Strategy 4: Padding Evasion
        Add legitimate words as padding to reduce entropy
        """
        domains = []
        common_words = ['the', 'and', 'for', 'with', 'from', 'this', 'that', 'your']
        
        for _ in range(count):
            # Malicious core
            malicious_core = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
            
            # Pad with common words
            padding = random.choice(common_words)
            tld = random.choice(self.legitimate_tlds)
            
            strategies = [
                # Prefix padding (the-x7k2m9n3p4.com)
                f"{padding}-{malicious_core}{tld}",
                
                # Suffix padding (x7k2m9n3p4-and.com)
                f"{malicious_core}-{padding}{tld}",
                
                # Both sides (for-x7k2m9n3-with.com)
                f"{padding}-{malicious_core}-{random.choice(common_words)}{tld}",
            ]
            
            domain = random.choice(strategies)
            entropy = _entropy(domain.split('.')[0])
            
            domains.append({
                'domain': domain,
                'entropy': entropy,
                'strategy': 'Padding Evasion (common words)',
                'expected_bypass': 'Stage 1 (entropy reduction)',
                'actual_threat': 'DGA'
            })
        
        return domains
    
    def generate_all_adversarial_domains(self):
        """Generate complete adversarial test set"""
        all_domains = []
        
        print("="*70)
        print("ADVERSARIAL DOMAIN GENERATOR - RED TEAM TESTING")
        print("="*70)
        
        # Strategy 1: Low Entropy
        print("\n[1/4] Generating Low Entropy Evasion domains...")
        low_entropy = self.generate_low_entropy_malicious(10)
        all_domains.extend(low_entropy)
        print(f"      Generated {len(low_entropy)} domains")
        
        # Strategy 2: Mid Entropy
        print("[2/4] Generating Mid Entropy (Goldilocks) domains...")
        mid_entropy = self.generate_mid_entropy_malicious(10)
        all_domains.extend(mid_entropy)
        print(f"      Generated {len(mid_entropy)} domains")
        
        # Strategy 3: Timing Jitter
        print("[3/4] Generating Timing Jitter test domains...")
        timing = self.generate_timing_jitter_simulation(5)
        all_domains.extend(timing)
        print(f"      Generated {len(timing)} domains")
        
        # Strategy 4: Padding
        print("[4/4] Generating Padding Evasion domains...")
        padding = self.generate_padding_evasion(5)
        all_domains.extend(padding)
        print(f"      Generated {len(padding)} domains")
        
        print(f"\n Total adversarial domains generated: {len(all_domains)}")
        print("="*70)
        
        return all_domains
    
    def export_to_file(self, domains, filename='adversarial_test_domains.txt'):
        """Export domains for testing"""
        with open(filename, 'w') as f:
            f.write("# ADVERSARIAL TEST DOMAINS - RED TEAM\n")
            f.write("# Generated for robustness testing\n\n")
            
            for domain_info in domains:
                f.write(f"{domain_info['domain']}\n")
        
        print(f" Exported to {filename}")


if __name__ == "__main__":
    # Generate adversarial domains
    generator = AdversarialDomainGenerator()
    adversarial_domains = generator.generate_all_adversarial_domains()
    
    # Display sample
    print("\n" + "="*70)
    print("SAMPLE ADVERSARIAL DOMAINS")
    print("="*70)
    
    for i, domain_info in enumerate(adversarial_domains[:10], 1):
        print(f"\n{i}. {domain_info['domain']}")
        print(f"   Entropy: {domain_info['entropy']:.2f}")
        print(f"   Strategy: {domain_info['strategy']}")
        print(f"   Expected to bypass: {domain_info['expected_bypass']}")
        print(f"   Actual threat: {domain_info['actual_threat']}")
    
    print("\n" + "="*70)
    
    # Export
    generator.export_to_file(adversarial_domains)
    
    # Save detailed results
    import json
    with open('adversarial_domains_detailed.json', 'w') as f:
        json.dump(adversarial_domains, f, indent=2)
    
    print(" Detailed results saved to adversarial_domains_detailed.json")
    print("\n Next Step: Run red_team_test.py to test these against DNS Shield!")