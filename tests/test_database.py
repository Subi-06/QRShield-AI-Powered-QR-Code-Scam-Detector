import pytest
import sys
import os
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database.db_manager import DatabaseManager

class TestDatabaseManager:
    def setup_method(self):
        # Use a fresh unique temp database for each test
        self._temp_dir = tempfile.mkdtemp()
        self.db_path = str(Path(self._temp_dir) / 'test_qrshield.db')
        self.db = DatabaseManager(db_path=self.db_path)
    
    def teardown_method(self):
        try:
            if hasattr(self, 'db') and hasattr(self.db, '_close'):
                self.db._close()
            import shutil
            if hasattr(self, '_temp_dir') and os.path.exists(self._temp_dir):
                shutil.rmtree(self._temp_dir, ignore_errors=True)
        except:
            pass
    
    def test_save_and_retrieve_scan(self):
        scan_data = {
            'content_type': 'url',
            'content_preview': 'https://example.com',
            'prediction_category': 'low_risk',
            'risk_level': 'low_risk',
            'model_probability': 0.15,
            'explanation_summary': 'No indicators found'
        }
        scan_id = self.db.save_scan(scan_data)
        assert scan_id is not None
        
        scan = self.db.get_scan_by_id(scan_id)
        assert scan is not None
        assert scan['content_type'] == 'url'
    
    def test_get_all_scans(self):
        for i in range(5):
            self.db.save_scan({
                'content_type': 'url',
                'content_preview': f'https://example{i}.com',
                'prediction_category': 'low_risk',
                'risk_level': 'low_risk'
            })
        scans = self.db.get_all_scans()
        assert len(scans) == 5
    
    def test_search_scans(self):
        self.db.save_scan({
            'content_type': 'url',
            'content_preview': 'https://google.com',
            'prediction_category': 'low_risk',
            'risk_level': 'low_risk'
        })
        results = self.db.search_scans('google')
        assert len(results) >= 1
    
    def test_filter_by_risk(self):
        self.db.save_scan({'content_type': 'url', 'content_preview': 'test', 'risk_level': 'high_risk', 'prediction_category': 'high_risk'})
        self.db.save_scan({'content_type': 'url', 'content_preview': 'test2', 'risk_level': 'low_risk', 'prediction_category': 'low_risk'})
        results = self.db.filter_scans(risk_level='high_risk')
        assert len(results) == 1
    
    def test_delete_scan(self):
        scan_id = self.db.save_scan({
            'content_type': 'url',
            'content_preview': 'test',
            'risk_level': 'low_risk',
            'prediction_category': 'low_risk'
        })
        assert self.db.delete_scan(scan_id) == True
        assert self.db.get_scan_by_id(scan_id) is None
    
    def test_clear_history(self):
        for i in range(3):
            self.db.save_scan({
                'content_type': 'url',
                'content_preview': f'test{i}',
                'risk_level': 'low_risk',
                'prediction_category': 'low_risk'
            })
        count = self.db.clear_history()
        assert count == 3
        assert len(self.db.get_all_scans()) == 0
    
    def test_get_statistics(self):
        self.db.save_scan({'content_type': 'url', 'content_preview': 'test', 'risk_level': 'high_risk', 'prediction_category': 'high_risk'})
        self.db.save_scan({'content_type': 'upi', 'content_preview': 'test', 'risk_level': 'low_risk', 'prediction_category': 'low_risk'})
        stats = self.db.get_statistics()
        assert stats['total_scans'] == 2
    
    def test_empty_database_stats(self):
        stats = self.db.get_statistics()
        assert stats['total_scans'] == 0
