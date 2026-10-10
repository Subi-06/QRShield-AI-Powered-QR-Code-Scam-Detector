import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.upi.verifier import UPIVerifier, UPIPaymentInfo, UPIVerificationResult

class TestUPIVerifier:
    def setup_method(self):
        self.verifier = UPIVerifier()
    
    def test_parse_valid_upi(self):
        uri = 'upi://pay?pa=merchant@upi&pn=Test%20Merchant&am=100.00&cu=INR'
        info = self.verifier.parse_upi_uri(uri)
        assert info is not None
        assert info.payee_address == 'merchant@upi'
        assert info.payee_name == 'Test Merchant'
        assert info.amount == 100.0
        assert info.currency == 'INR'
    
    def test_parse_invalid_uri(self):
        info = self.verifier.parse_upi_uri('https://google.com')
        assert info is None
    
    def test_parse_empty_uri(self):
        info = self.verifier.parse_upi_uri('')
        assert info is None
    
    def test_missing_payee(self):
        uri = 'upi://pay?pn=Test&am=100'
        result = self.verifier.verify(uri)
        assert len(result.concerns) > 0 or result.status != 'verification_required'
    
    def test_high_amount_flag(self):
        uri = 'upi://pay?pa=merchant@upi&pn=Test&am=100000&cu=INR'
        result = self.verifier.verify(uri)
        assert any('amount' in w.lower() or 'high' in w.lower() for w in result.warnings + result.concerns)
    
    def test_missing_name_flag(self):
        uri = 'upi://pay?pa=merchant@upi&am=100&cu=INR'
        result = self.verifier.verify(uri)
        assert any('name' in w.lower() for w in result.warnings + result.info_messages)
    
    def test_invalid_currency(self):
        uri = 'upi://pay?pa=merchant@upi&pn=Test&am=100&cu=USD'
        result = self.verifier.verify(uri)
        assert any('currency' in w.lower() for w in result.warnings + result.concerns)
    
    def test_negative_amount(self):
        uri = 'upi://pay?pa=merchant@upi&pn=Test&am=-50&cu=INR'
        result = self.verifier.verify(uri)
        assert len(result.concerns) > 0
    
    def test_result_has_disclaimer(self):
        uri = 'upi://pay?pa=merchant@upi&pn=Test&am=100&cu=INR'
        result = self.verifier.verify(uri)
        assert len(result.recommendations) > 0
    
    def test_suspicious_note(self):
        uri = 'upi://pay?pa=merchant@upi&pn=Test&am=100&cu=INR&tn=URGENT%20lottery%20winner'
        result = self.verifier.verify(uri)
        assert result.risk_level in ['medium', 'high']
    
    def test_complete_verification(self):
        uri = 'upi://pay?pa=merchant@upi&pn=Verified%20Merchant&am=500.00&cu=INR&tr=TXN123'
        result = self.verifier.verify(uri)
        assert result.status in ['verification_required', 'info_incomplete', 'potential_concern']
        assert result.payment_info is not None
