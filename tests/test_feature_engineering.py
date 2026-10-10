import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ml.feature_engineering import URLFeatureExtractor, get_feature_descriptions

class TestURLFeatureExtractor:
    def setup_method(self):
        self.extractor = URLFeatureExtractor()
    
    def test_feature_count(self):
        """Should extract exactly 35 features"""
        features = self.extractor.extract_features('https://www.google.com')
        assert len(features) == 35
    
    def test_all_features_numeric(self):
        """All features must be numeric"""
        features = self.extractor.extract_features('https://example.com/path?q=test')
        for name, value in features.items():
            assert isinstance(value, (int, float)), f'{name} is {type(value)}'
    
    def test_https_detection(self):
        features_https = self.extractor.extract_features('https://example.com')
        features_http = self.extractor.extract_features('http://example.com')
        assert features_https['is_https'] == 1
        assert features_http['is_https'] == 0
    
    def test_ip_address_detection(self):
        features = self.extractor.extract_features('http://192.168.1.1/login')
        assert features['has_ip_address'] == 1
        features_normal = self.extractor.extract_features('https://google.com')
        assert features_normal['has_ip_address'] == 0
    
    def test_suspicious_keywords(self):
        features = self.extractor.extract_features('http://login-verify-secure.evil.com/account')
        assert features['has_suspicious_keyword'] == 1
        assert features['num_suspicious_keywords'] >= 3
    
    def test_url_shortener_detection(self):
        features = self.extractor.extract_features('https://bit.ly/abc123')
        assert features['is_url_shortener'] == 1
    
    def test_subdomain_count(self):
        features = self.extractor.extract_features('https://a.b.c.example.com/path')
        assert features['num_subdomains'] >= 3
    
    def test_at_sign_detection(self):
        features = self.extractor.extract_features('https://user@example.com/path')
        assert features['has_at_sign'] == 1
    
    def test_empty_url(self):
        features = self.extractor.extract_features('')
        assert len(features) == 35  # Should return defaults
    
    def test_malformed_url(self):
        features = self.extractor.extract_features('not-a-url')
        assert len(features) == 35
    
    def test_url_entropy(self):
        features = self.extractor.extract_features('https://www.google.com')
        assert features['url_entropy'] > 0
    
    def test_special_char_ratio(self):
        features = self.extractor.extract_features('https://evil.com/!!@@##$$%%')
        assert features['special_char_ratio'] > 0
    
    def test_dataframe_extraction(self):
        urls = ['https://google.com', 'http://evil.com/phish']
        df = self.extractor.extract_features_dataframe(urls)
        assert len(df) == 2
        assert len(df.columns) == 35
    
    def test_feature_names_consistency(self):
        names = self.extractor.get_feature_names()
        features = self.extractor.extract_features('https://example.com')
        assert set(names) == set(features.keys())
    
    def test_feature_descriptions(self):
        descriptions = get_feature_descriptions()
        assert len(descriptions) == 35
        for name in self.extractor.get_feature_names():
            assert name in descriptions
    
    def test_port_detection(self):
        features = self.extractor.extract_features('http://example.com:8080/path')
        assert features['has_port'] == 1
    
    def test_encoded_chars(self):
        features = self.extractor.extract_features('https://example.com/path%20with%20spaces')
        assert features['has_encoded_chars'] == 1
    
    def test_www_detection(self):
        features = self.extractor.extract_features('https://www.example.com')
        assert features['has_www'] == 1
        features_no = self.extractor.extract_features('https://example.com')
        assert features_no['has_www'] == 0
