import pytest
import sys
import numpy as np
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.security.sanitizer import InputSanitizer, escape_html, is_safe_redirect

class TestInputSanitizer:
    def setup_method(self):
        self.sanitizer = InputSanitizer()
    
    def test_sanitize_text_escapes_html(self):
        result = self.sanitizer.sanitize_text('<script>alert(1)</script>')
        assert '<script>' not in result
        assert '&lt;script&gt;' in result
    
    def test_sanitize_text_strips_nulls(self):
        result = self.sanitizer.sanitize_text('hello\x00world')
        assert '\x00' not in result
    
    def test_sanitize_text_length_limit(self):
        long_text = 'a' * 20000
        result = self.sanitizer.sanitize_text(long_text)
        assert len(result) <= 10000
    
    def test_sanitize_url_valid_https(self):
        result = self.sanitizer.sanitize_url('https://example.com/path')
        assert result == 'https://example.com/path'
    
    def test_sanitize_url_rejects_javascript(self):
        result = self.sanitizer.sanitize_url('javascript:alert(1)')
        assert result is None
    
    def test_sanitize_url_rejects_data(self):
        result = self.sanitizer.sanitize_url('data:text/html,<script>alert(1)</script>')
        assert result is None
    
    def test_sanitize_url_rejects_credentials(self):
        result = self.sanitizer.sanitize_url('https://user:pass@example.com')
        assert result is None
    
    def test_content_type_url(self):
        assert self.sanitizer.validate_content_type('https://google.com') == 'url'
    
    def test_content_type_upi(self):
        assert self.sanitizer.validate_content_type('upi://pay?pa=test@upi') == 'upi'
    
    def test_content_type_email(self):
        assert self.sanitizer.validate_content_type('mailto:test@example.com') == 'email'
    
    def test_content_type_phone(self):
        assert self.sanitizer.validate_content_type('tel:+1234567890') == 'phone'
    
    def test_content_type_text(self):
        assert self.sanitizer.validate_content_type('hello world') == 'text'
    
    def test_private_ip_detection(self):
        assert self.sanitizer.is_private_ip('127.0.0.1') == True
        assert self.sanitizer.is_private_ip('192.168.1.1') == True
        assert self.sanitizer.is_private_ip('10.0.0.1') == True
    
    def test_public_ip_not_private(self):
        assert self.sanitizer.is_private_ip('8.8.8.8') == False

class TestEscapeHtml:
    def test_basic_escape(self):
        assert '&lt;' in escape_html('<div>')
    
    def test_empty_string(self):
        assert escape_html('') == ''
    
    def test_safe_text_unchanged(self):
        assert escape_html('hello world') == 'hello world'

class TestSafeRedirect:
    def test_public_url_safe(self):
        assert is_safe_redirect('https://google.com') == True
    
    def test_private_ip_unsafe(self):
        assert is_safe_redirect('http://192.168.1.1') == False
    
    def test_localhost_unsafe(self):
        assert is_safe_redirect('http://127.0.0.1') == False
