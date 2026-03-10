"""
Whitelist Integration Tests
Comprehensive tests for whitelist functionality
"""

import pytest
import json
import tempfile
from pathlib import Path
from src.whitelist_manager import (
    WhitelistManager, WhitelistEntry, WhitelistType, get_whitelist_manager
)


@pytest.fixture
def temp_data_dir():
    """Create temporary data directory"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def manager(temp_data_dir):
    """Create whitelist manager with temp directory"""
    return WhitelistManager(data_dir=temp_data_dir)


class TestWhitelistEntry:
    """Test WhitelistEntry class"""
    
    def test_exact_match(self):
        """Test exact pattern matching"""
        entry = WhitelistEntry("my_key_123", entry_type="EXACT")
        assert entry.matches("my_key_123")
        assert not entry.matches("my_key_1234")
    
    def test_regex_match(self):
        """Test regex pattern matching"""
        entry = WhitelistEntry("sk_test_.*", entry_type="REGEX")
        assert entry.matches("sk_test_123abc")
        assert entry.matches("sk_test_xyz")
        assert not entry.matches("sk_live_123abc")
    
    def test_disabled_entry(self):
        """Test disabled entries don't match"""
        entry = WhitelistEntry("test", enabled=False)
        assert not entry.matches("test")
    
    def test_expired_entry(self):
        """Test expired entries don't match"""
        entry = WhitelistEntry("test", expires_at="2020-01-01T00:00:00")
        assert not entry.matches("test")
    
    def test_entry_serialization(self):
        """Test entry to/from dict"""
        original = WhitelistEntry("pattern", description="test desc", tags=["tag1"])
        data = original.to_dict()
        restored = WhitelistEntry.from_dict(data)
        assert restored.pattern == original.pattern
        assert restored.description == original.description
        assert restored.tags == original.tags


class TestWhitelistManager:
    """Test WhitelistManager class"""
    
    def test_add_entry(self, manager):
        """Test adding entry"""
        success, msg = manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test_pattern"
        )
        assert success
        assert "test_pattern" in manager.get_patterns(
            WhitelistType.GLOBAL.value,
            "default"
        )
    
    def test_duplicate_entry_rejected(self, manager):
        """Test duplicate entries are rejected"""
        manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test"
        )
        success, msg = manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test"
        )
        assert not success
        assert "already exists" in msg
    
    def test_invalid_regex_rejected(self, manager):
        """Test invalid regex is rejected"""
        success, msg = manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="[invalid(regex",
            entry_type="REGEX"
        )
        assert not success
    
    def test_remove_entry(self, manager):
        """Test removing entry"""
        manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test"
        )
        success, msg = manager.remove_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test"
        )
        assert success
        assert "test" not in manager.get_patterns(
            WhitelistType.GLOBAL.value,
            "default"
        )
    
    def test_toggle_entry(self, manager):
        """Test toggling entry on/off"""
        manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test"
        )
        
        # Disable
        manager.toggle_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test",
            enabled=False
        )
        assert "test" not in manager.get_patterns(
            WhitelistType.GLOBAL.value,
            "default"
        )
        
        # Re-enable
        manager.toggle_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test",
            enabled=True
        )
        assert "test" in manager.get_patterns(
            WhitelistType.GLOBAL.value,
            "default"
        )
    
    def test_check_matches_global(self, manager):
        """Test checking matches in global whitelist"""
        manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test_key"
        )
        
        is_whitelisted, patterns = manager.check_matches(
            "test_key",
            global_list=True
        )
        assert is_whitelisted
        assert "test_key" in patterns
    
    def test_check_matches_profile(self, manager):
        """Test checking matches in profile whitelist"""
        manager.add_entry(
            list_type=WhitelistType.PROFILE.value,
            list_id="fintech",
            pattern="sk_test_.*",
            entry_type="REGEX"
        )
        
        is_whitelisted, patterns = manager.check_matches(
            "sk_test_123abc",
            profile="fintech"
        )
        assert is_whitelisted
    
    def test_persistence(self, temp_data_dir):
        """Test whitelists persist to disk"""
        # Create and populate manager
        mgr1 = WhitelistManager(data_dir=temp_data_dir)
        mgr1.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="persistent_pattern"
        )
        
        # Create new manager from same directory
        mgr2 = WhitelistManager(data_dir=temp_data_dir)
        
        # Check entry exists
        patterns = mgr2.get_patterns(
            WhitelistType.GLOBAL.value,
            "default"
        )
        assert "persistent_pattern" in patterns
    
    def test_audit_logging(self, manager):
        """Test audit log is created"""
        manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test",
            created_by="test_user"
        )
        
        logs = manager.get_audit_log()
        assert len(logs) > 0
        assert logs[-1]["action"] == "ADD"
        assert logs[-1]["user"] == "test_user"
    
    def test_list_whitelists(self, manager):
        """Test listing all whitelists"""
        manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="test1"
        )
        manager.add_entry(
            list_type=WhitelistType.PROFILE.value,
            list_id="fintech",
            pattern="test2"
        )
        
        status = manager.list_whitelists()
        assert status["GLOBAL"]["default"]["total_entries"] == 1
        assert status["PROFILE"]["fintech"]["total_entries"] == 1


class TestWhitelistIntegration:
    """Integration tests for whitelist with redaction"""
    
    def test_whitelist_prevents_redaction(self):
        """Test that whitelisted values aren't redacted"""
        from src.redactor import redact_content
        
        api_key = "sk_test_123456789"
        content = f"Use this key: {api_key}"
        whitelist = [api_key]
        
        sanitized, mods = redact_content(content, whitelist=whitelist)
        assert api_key in sanitized
        assert "[REDACTED" not in sanitized
    
    def test_non_whitelisted_gets_redacted(self):
        """Test that non-whitelisted values are redacted"""
        from src.redactor import redact_content
        
        api_key = "sk_test_123456789"
        content = f"Use this key: {api_key}"
        whitelist = []
        
        sanitized, mods = redact_content(content, whitelist=whitelist)
        assert api_key not in sanitized
        assert "[REDACTED" in sanitized
    
    def test_regex_whitelist_pattern(self):
        """Test regex patterns in whitelist"""
        from src.redactor import redact_content
        
        content = "Emails: test_user_1@staging.com and real_user@example.com"
        whitelist = [".*@staging.com"]
        
        sanitized, mods = redact_content(content, whitelist=whitelist)
        assert "@staging.com" in sanitized
        assert "example.com" not in sanitized


class TestWhitelistEdgeCases:
    """Test edge cases and error handling"""
    
    def test_empty_pattern(self, manager):
        """Test empty pattern is rejected"""
        success, msg = manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern=""
        )
        assert not success
    
    def test_very_long_pattern(self, manager):
        """Test handling of very long patterns"""
        long_pattern = "x" * 10000
        success, msg = manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern=long_pattern
        )
        assert success
    
    def test_unicode_pattern(self, manager):
        """Test unicode in patterns"""
        success, msg = manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern="пароль_123"
        )
        assert success
    
    def test_special_characters_in_pattern(self, manager):
        """Test special characters in exact patterns"""
        pattern = "test!@#$%^&*()"
        success, msg = manager.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern=pattern,
            entry_type="EXACT"
        )
        assert success


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
