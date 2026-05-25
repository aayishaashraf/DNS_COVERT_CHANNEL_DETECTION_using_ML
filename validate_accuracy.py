"""
Validate DNS Shield Accuracy
Checks: Accuracy, Recall, Precision, FPR, FNR, LSTM Usage
"""

import random
import string
from threat_detector import ThreatDetector

def generate_test_set(n=2000):
    """Generate test domains (not in training)"""
    benign = []
    malicious = []
    
    # Benign (1000)
    real = ['google.com', 'facebook.com', 'amazon.com', 'twitter.com', 
            'netflix.com', 'github.com', 'apple.com', 'microsoft.com']
    
    for _ in range(1000):
        r = random.random()
        if r < 0.70:
            benign.append(random.choice(real))
        elif r < 0.90:
            benign.append(f'{"".join(random.choices(["api", "cdn", "web"], k=1))[0]}.{random.choice(real)}')
        else:
            benign.append(f'v{random.randint(1,4)}.{random.choice(real)}')
    
    # Malicious (1000)
    # 40% Pure DGA (high entropy)
    for _ in range(400):
        length = random.randint(20, 30)
        domain = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        malicious.append(f'{domain}.com')
    
    # 15% DNS Tunneling
    for _ in range(150):
        length = random.randint(40, 60)
        encoded = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
        malicious.append(f'{encoded}.attacker.com')
    
    # 12% Typosquatting
    for _ in range(120):
        target = random.choice(['google', 'facebook', 'paypal'])
        typo = target.replace('o', '0').replace('l', '1').replace('a', '4')
        malicious.append(f'{typo}.com')
    
    # 12% Structured DGA
    for _ in range(120):
        word = random.choice(['data', 'update', 'system'])
        num = random.randint(100, 9999)
        malicious.append(f'{word}{num}.com')
    
    # 10% C2 Beaconing
    for _ in range(100):
        service = random.choice(['check', 'verify', 'status'])
        malicious.append(f'{service}-system.com')
    
    # 6% IBHH
    for _ in range(60):
        base = random.choice(['data', 'chunk', 'part'])
        malicious.append(f'{base}{random.randint(1, 500)}.exfil.com')
    
    # 3% Homograph
    for _ in range(30):
        target = random.choice(['google', 'paypal'])
        modified = target.replace('o', '0').replace('a', '4')
        malicious.append(f'{modified}.com')
    
    # 2% Fast Flux
    for _ in range(20):
        malicious.append(f'{random.choice(["update", "download"])}.com')
    
    return benign, malicious


def main():
    print('='*70)
    print('DNS SHIELD - ACCURACY VALIDATION')
    print('='*70)
    
    # Initialize detector
    detector = ThreatDetector()
    if not detector.loaded:
        print(' Failed to load models!')
        return
    
    # Generate test set
    print('\\n Generating test set...')
    benign, malicious = generate_test_set(2000)
    print(f'   Benign: {len(benign)}')
    print(f'   Malicious: {len(malicious)}')
    
    # Test
    print('\\n Testing...')
    tp, fp, tn, fn = 0, 0, 0, 0
    stage1_low, stage1_high, stage2_lstm = 0, 0, 0
    
    # Test benign
    for domain in benign:
        is_mal, threat_type, conf, exp = detector.check_domain(domain)
        
        # Count stage
        if 'Low entropy' in exp or 'Whitelisted' in exp:
            stage1_low += 1
        elif 'High entropy' in exp:
            stage1_high += 1
        else:
            stage2_lstm += 1
        
        if is_mal:
            fp += 1
        else:
            tn += 1
    
    # Test malicious
    for domain in malicious:
        is_mal, threat_type, conf, exp = detector.check_domain(domain)
        
        # Count stage
        if 'Low entropy' in exp or 'Whitelisted' in exp:
            stage1_low += 1
        elif 'High entropy' in exp:
            stage1_high += 1
        else:
            stage2_lstm += 1
        
        if is_mal:
            tp += 1
        else:
            fn += 1
    
    # Calculate metrics
    total = len(benign) + len(malicious)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    # Print results
    print('\\n' + '='*70)
    print('RESULTS')
    print('='*70)
    
    print(f'\\n Confusion Matrix:')
    print(f'   TP: {tp:4d}  FP: {fp:4d}')
    print(f'   FN: {fn:4d}  TN: {tn:4d}')
    
    print(f'\\n Performance Metrics:')
    print(f'   Accuracy:  {accuracy*100:6.2f}%')
    print(f'   Precision: {precision*100:6.2f}%')
    print(f'   Recall:    {recall*100:6.2f}%')
    print(f'   F1-Score:  {f1*100:6.2f}%')
    print(f'   FPR:       {fpr*100:6.2f}%')
    print(f'   FNR:       {fnr*100:6.2f}%')
    
    print(f'\\n Stage Distribution:')
    print(f'   Stage 1 (Low):  {stage1_low:4d} ({stage1_low/total*100:5.1f}%)')
    print(f'   Stage 1 (High): {stage1_high:4d} ({stage1_high/total*100:5.1f}%)')
    print(f'   Stage 2 (LSTM): {stage2_lstm:4d} ({stage2_lstm/total*100:5.1f}%)')
    print(f'\\n   Total Stage 1: {(stage1_low+stage1_high)/total*100:.1f}%')
    print(f'   Total Stage 2: {stage2_lstm/total*100:.1f}%')
    
    # Check targets
    print('\\n' + '='*70)
    print('TARGET VALIDATION')
    print('='*70)
    
    targets_met = []
    targets_missed = []
    
    # Accuracy
    if 95 <= accuracy*100 <= 97:
        targets_met.append(f' Accuracy: {accuracy*100:.2f}% (target: 95-97%)')
    elif 93 <= accuracy*100 < 95:
        targets_missed.append(f'  Accuracy: {accuracy*100:.2f}% (target: 95-97%, close!)')
    else:
        targets_missed.append(f' Accuracy: {accuracy*100:.2f}% (target: 95-97%)')
    
    # Recall
    if 95 <= recall*100 <= 98:
        targets_met.append(f' Recall: {recall*100:.2f}% (target: 95-98%)')
    elif 93 <= recall*100 < 95:
        targets_missed.append(f'  Recall: {recall*100:.2f}% (target: 95-98%, close!)')
    else:
        targets_missed.append(f' Recall: {recall*100:.2f}% (target: 95-98%)')
    
    # Precision
    if 95 <= precision*100 <= 97:
        targets_met.append(f' Precision: {precision*100:.2f}% (target: 95-97%)')
    elif 93 <= precision*100 < 95:
        targets_missed.append(f'  Precision: {precision*100:.2f}% (target: 95-97%, close!)')
    else:
        targets_missed.append(f' Precision: {precision*100:.2f}% (target: 95-97%)')
    
    # FPR
    if fpr*100 < 5:
        targets_met.append(f' FPR: {fpr*100:.2f}% (target: <5%)')
    else:
        targets_missed.append(f' FPR: {fpr*100:.2f}% (target: <5%)')
    
    # FNR
    if fnr*100 < 1:
        targets_met.append(f' FNR: {fnr*100:.2f}% (target: <1%)')
    elif fnr*100 < 3:
        targets_missed.append(f'  FNR: {fnr*100:.2f}% (target: <1%, close!)')
    else:
        targets_missed.append(f' FNR: {fnr*100:.2f}% (target: <1%)')
    
    # LSTM Usage
    if stage2_lstm/total*100 <= 21:
        targets_met.append(f' LSTM Usage: {stage2_lstm/total*100:.1f}% (target: 15-21%)')
    elif stage2_lstm/total*100 <= 25:
        targets_missed.append(f'  LSTM Usage: {stage2_lstm/total*100:.1f}% (target: 15-21%, acceptable)')
    else:
        targets_missed.append(f' LSTM Usage: {stage2_lstm/total*100:.1f}% (target: 15-21%)')
    
    print()
    for t in targets_met:
        print(t)
    for t in targets_missed:
        print(t)
    
    print('\\n' + '='*70)
    if len(targets_missed) == 0:
        print(' ALL TARGETS MET! System ready for deployment!')
    elif len(targets_missed) <= 2 and all('__' in t for t in targets_missed):
        print(' TARGETS MOSTLY MET! System acceptable for deployment.')
    else:
        print('  Some targets need adjustment.')
    print('='*70)


if __name__ == '__main__':
    main()