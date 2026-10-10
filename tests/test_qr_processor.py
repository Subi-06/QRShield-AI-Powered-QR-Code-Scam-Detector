import pytest
import sys
import numpy as np
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.qr_processor.decoder import QRDecoder, QRDecodeResult
from src.qr_processor.validator import ImageValidator

class TestQRDecoder:
    def setup_method(self):
        self.decoder = QRDecoder()
    
    def test_decode_result_structure(self):
        result = QRDecodeResult(
            success=False, content=None, content_type=None,
            error_message='test', decoder_used=None, raw_bytes=None
        )
        assert result.success == False
        assert result.error_message == 'test'
    
    def test_content_type_url(self):
        # Test content type detection
        from src.qr_processor.decoder import QRDecoder
        assert QRDecoder.detect_content_type('https://example.com') == 'url'
        assert QRDecoder.detect_content_type('http://example.com') == 'url'
        assert QRDecoder.detect_content_type('upi://pay?pa=test@upi') == 'upi'
        assert QRDecoder.detect_content_type('just plain text') == 'text'
    
    def test_invalid_image_bytes(self):
        result = self.decoder.decode_from_image(b'not an image')
        assert result.success == False
    
    def test_empty_image_bytes(self):
        result = self.decoder.decode_from_image(b'')
        assert result.success == False
    
    def test_none_camera_frame(self):
        # Create a blank frame with no QR code
        blank = np.zeros((100, 100, 3), dtype=np.uint8)
        result = self.decoder.decode_from_camera_frame(blank)
        assert result.success == False

class TestImageValidator:
    def setup_method(self):
        self.validator = ImageValidator()
    
    def test_none_upload(self):
        is_valid, msg, data = self.validator.validate_upload(None)
        assert is_valid == False
    
    def test_dimension_too_large(self):
        large_image = np.zeros((5000, 5000, 3), dtype=np.uint8)
        is_valid, msg = self.validator.validate_dimensions(large_image)
        assert is_valid == False
    
    def test_dimension_too_small(self):
        tiny_image = np.zeros((5, 5, 3), dtype=np.uint8)
        is_valid, msg = self.validator.validate_dimensions(tiny_image)
        assert is_valid == False
    
    def test_valid_dimensions(self):
        normal_image = np.zeros((500, 500, 3), dtype=np.uint8)
        is_valid, msg = self.validator.validate_dimensions(normal_image)
        assert is_valid == True
