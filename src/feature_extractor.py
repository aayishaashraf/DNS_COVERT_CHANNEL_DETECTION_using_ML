from pathlib import Path
import pandas as pd
import numpy as np
import math
from collections import Counter

class DNSFeatureExtractor:
    """Extracts linguistic and statistical features from DNS domain strings."""

    def __init__(self):
        self.vowels = set('aeiou')

    def extract_features(self, domain):
        """Calculates 22 features for a single domain string."""
        # Handle non-string or NaN inputs
        if not isinstance(domain, str) or domain.lower() == 'nan' or not domain:
            return {f"f_{i}": 0.0 for i in range(22)}

        domain = domain.lower()
        
        # 1. Basic Length
        length = len(domain)
        
        # 2. Shannon Entropy
        prob = [n/length for n in Counter(domain).values()]
        entropy = -sum(p * math.log2(p) for p in prob)

        # 3. Digit count
        digits = sum(c.isdigit() for c in domain)
        
        # 4. Character counts
        vowel_count = sum(c in self.vowels for c in domain)
        consonant_count = sum(c.isalpha() and c not in self.vowels for c in domain)
        special_count = sum(not c.isalnum() for c in domain)
        
        # 5. Segment (label) analysis (e.g., 'sub.example.com' has 3 segments)
        segments = domain.split('.')
        num_segments = len(segments)
        max_segment_len = max(len(s) for s in segments) if segments else 0
        avg_segment_len = length / num_segments if num_segments > 0 else 0

        # 6. Specific character counts
        hyphen_count = domain.count('-')
        dot_count = domain.count('.')

        # Compile the feature dictionary (Exactly 22 features)
        features = {
            'length': length,
            'entropy': entropy,
            'digit_count': digits,
            'digit_ratio': digits / length if length > 0 else 0,
            'vowel_count': vowel_count,
            'vowel_ratio': vowel_count / length if length > 0 else 0,
            'consonant_count': consonant_count,
            'consonant_ratio': consonant_count / length if length > 0 else 0,
            'special_char_count': special_count,
            'special_char_ratio': special_count / length if length > 0 else 0,
            'num_segments': num_segments,
            'max_segment_len': max_segment_len,
            'avg_segment_len': avg_segment_len,
            'hyphen_count': hyphen_count,
            'dot_count': dot_count,
            'unique_chars': len(set(domain)),
            'non_alphanumeric_ratio': (special_count) / length if length > 0 else 0,
            'hex_chars': sum(c in '0123456789abcdef' for c in domain),
            'consecutive_digits': self._max_consecutive(domain, str.isdigit),
            'consecutive_consonants': self._max_consecutive(domain, lambda c: c.isalpha() and c not in self.vowels),
            'consecutive_vowels': self._max_consecutive(domain, lambda c: c in self.vowels),
            'is_ip_format': 1 if all(c.isdigit() or c == '.' for c in domain) else 0
        }
        return features

    def _max_consecutive(self, s, criteria):
        """Helper to find maximum consecutive characters matching a criteria."""
        max_count = 0
        current_count = 0
        for char in s:
            if criteria(char):
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        return max_count

    def process_dataframe(self, df):
        """Converts a DataFrame of domains into a numeric feature DataFrame."""
        print(f"⏳ Extracting features from {len(df)} domains...")
        
        # Ensure 'domain' exists and is treated as string
        if 'domain' not in df.columns:
            raise KeyError("DataFrame must contain a 'domain' column.")

        # Extract features for each row
        feature_data = [self.extract_features(str(d)) for d in df['domain']]
        
        # Create new DF
        features_df = pd.DataFrame(feature_data)
        
        # Keep labels for training
        if 'label' in df.columns:
            features_df['label'] = df['label'].values
            
        # Keep domains for debugging
        features_df['domain'] = df['domain'].values
        
        print(f"✅ Feature extraction complete. Shape: {features_df.shape}")
        return features_df

    def get_feature_statistics(self, df):
        """Displays descriptive stats for the extracted features."""
        numeric_df = df.drop(columns=['domain', 'label'], errors='ignore')
        print("\n📊 Feature Statistics (First 5):")
        print(numeric_df.describe().iloc[:, :5])
        
    def save_features(self, df, filename='processed_features.csv'):
        """Saves the extracted features to the data/processed directory."""
        path = Path('data/processed') / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(path, index=False)
        print(f"💾 Features saved to {path}")