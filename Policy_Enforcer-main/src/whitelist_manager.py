"""
Whitelist Manager
Full-featured whitelist management with persistence, validation, and auditing.
"""

import json
import re
import os
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
from pathlib import Path
import hashlib
from enum import Enum


class WhitelistType(Enum):
    """Types of whitelists"""
    GLOBAL = "GLOBAL"           # System-wide
    PROFILE = "PROFILE"         # Policy profile-specific
    ORGANIZATION = "ORGANIZATION"  # Organization-specific
    TEMPORARY = "TEMPORARY"     # Temporary (expires)


class WhitelistEntry:
    """Represents a single whitelist entry"""
    
    def __init__(
        self,
        pattern: str,
        description: str = "",
        entry_type: str = "EXACT",  # EXACT or REGEX
        created_by: str = "system",
        created_at: str = None,
        expires_at: Optional[str] = None,
        tags: List[str] = None,
        enabled: bool = True
    ):
        self.pattern = pattern
        self.description = description
        self.entry_type = entry_type  # EXACT or REGEX
        self.created_by = created_by
        self.created_at = created_at or datetime.utcnow().isoformat()
        self.expires_at = expires_at
        self.tags = tags or []
        self.enabled = enabled
        self.pattern_hash = self._hash_pattern()
        
    def _hash_pattern(self) -> str:
        """Create hash of pattern for deduplication"""
        return hashlib.sha256(self.pattern.encode()).hexdigest()[:16]
    
    def is_expired(self) -> bool:
        """Check if entry is expired"""
        if not self.expires_at:
            return False
        return datetime.fromisoformat(self.expires_at) < datetime.utcnow()
    
    def matches(self, text: str) -> bool:
        """Check if text matches this entry"""
        if not self.enabled or self.is_expired():
            return False
        
        try:
            if self.entry_type == "EXACT":
                return text == self.pattern
            elif self.entry_type == "REGEX":
                return bool(re.search(self.pattern, text))
        except re.error:
            # Invalid regex - treat as literal
            return text == self.pattern
        
        return False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "pattern": self.pattern,
            "description": self.description,
            "type": self.entry_type,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "tags": self.tags,
            "enabled": self.enabled,
            "hash": self.pattern_hash
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'WhitelistEntry':
        """Create from dictionary"""
        return cls(
            pattern=data["pattern"],
            description=data.get("description", ""),
            entry_type=data.get("type", "EXACT"),
            created_by=data.get("created_by", "system"),
            created_at=data.get("created_at"),
            expires_at=data.get("expires_at"),
            tags=data.get("tags", []),
            enabled=data.get("enabled", True)
        )


class WhitelistManager:
    """Manages whitelists with persistence and validation"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        self.whitelists_file = self.data_dir / "whitelists.json"
        self.audit_log_file = self.data_dir / "whitelist_audit.log"
        
        self.whitelists: Dict[str, Dict[str, List[WhitelistEntry]]] = {
            WhitelistType.GLOBAL.value: {},
            WhitelistType.PROFILE.value: {},
            WhitelistType.ORGANIZATION.value: {},
            WhitelistType.TEMPORARY.value: {}
        }
        
        self.load_from_disk()
    
    def load_from_disk(self):
        """Load whitelists from persistent storage"""
        if self.whitelists_file.exists():
            try:
                with open(self.whitelists_file, 'r') as f:
                    data = json.load(f)
                    for list_type in self.whitelists:
                        if list_type in data:
                            for list_id, entries in data[list_type].items():
                                self.whitelists[list_type][list_id] = [
                                    WhitelistEntry.from_dict(e) for e in entries
                                ]
            except Exception as e:
                print(f"Warning: Could not load whitelists: {e}")
    
    def save_to_disk(self):
        """Save whitelists to persistent storage"""
        try:
            data = {}
            for list_type in self.whitelists:
                data[list_type] = {}
                for list_id, entries in self.whitelists[list_type].items():
                    data[list_type][list_id] = [e.to_dict() for e in entries]
            
            with open(self.whitelists_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving whitelists: {e}")
    
    def add_entry(
        self,
        list_type: str,
        list_id: str,
        pattern: str,
        description: str = "",
        entry_type: str = "EXACT",
        created_by: str = "admin",
        expires_at: Optional[str] = None,
        tags: List[str] = None
    ) -> Tuple[bool, str]:
        """
        Add entry to whitelist
        
        Returns:
            (success, message)
        """
        # Validate
        if not pattern or not pattern.strip():
            return False, "Pattern cannot be empty"
        
        if entry_type not in ["EXACT", "REGEX"]:
            return False, f"Invalid type: {entry_type}"
        
        # Validate regex if needed
        if entry_type == "REGEX":
            try:
                re.compile(pattern)
            except re.error as e:
                return False, f"Invalid regex: {e}"
        
        # Initialize list if doesn't exist
        if list_type not in self.whitelists or list_id not in self.whitelists[list_type]:
            self.whitelists[list_type][list_id] = []
        
        # Check for duplicates
        for entry in self.whitelists[list_type][list_id]:
            if entry.pattern == pattern:
                return False, "Entry already exists"
        
        # Add entry
        new_entry = WhitelistEntry(
            pattern=pattern,
            description=description,
            entry_type=entry_type,
            created_by=created_by,
            expires_at=expires_at,
            tags=tags or []
        )
        
        self.whitelists[list_type][list_id].append(new_entry)
        self.save_to_disk()
        self._audit_log("ADD", list_type, list_id, pattern, created_by)
        
        return True, f"Entry added: {pattern}"
    
    def remove_entry(
        self,
        list_type: str,
        list_id: str,
        pattern: str,
        removed_by: str = "admin"
    ) -> Tuple[bool, str]:
        """Remove entry from whitelist"""
        if list_type not in self.whitelists or list_id not in self.whitelists[list_type]:
            return False, "Whitelist not found"
        
        entries = self.whitelists[list_type][list_id]
        original_count = len(entries)
        self.whitelists[list_type][list_id] = [e for e in entries if e.pattern != pattern]
        
        if len(self.whitelists[list_type][list_id]) < original_count:
            self.save_to_disk()
            self._audit_log("REMOVE", list_type, list_id, pattern, removed_by)
            return True, f"Entry removed: {pattern}"
        
        return False, "Entry not found"
    
    def toggle_entry(
        self,
        list_type: str,
        list_id: str,
        pattern: str,
        enabled: bool,
        toggled_by: str = "admin"
    ) -> Tuple[bool, str]:
        """Enable/disable entry"""
        if list_type not in self.whitelists or list_id not in self.whitelists[list_type]:
            return False, "Whitelist not found"
        
        for entry in self.whitelists[list_type][list_id]:
            if entry.pattern == pattern:
                entry.enabled = enabled
                self.save_to_disk()
                self._audit_log(
                    "TOGGLE" if enabled else "DISABLE",
                    list_type,
                    list_id,
                    pattern,
                    toggled_by
                )
                return True, f"Entry {'enabled' if enabled else 'disabled'}: {pattern}"
        
        return False, "Entry not found"
    
    def get_patterns(
        self,
        list_type: str,
        list_id: str
    ) -> List[str]:
        """Get all active patterns for a whitelist"""
        if list_type not in self.whitelists or list_id not in self.whitelists[list_type]:
            return []
        
        return [
            e.pattern
            for e in self.whitelists[list_type][list_id]
            if e.enabled and not e.is_expired()
        ]
    
    def get_all_entries(
        self,
        list_type: str,
        list_id: str,
        include_disabled: bool = False
    ) -> List[Dict]:
        """Get all entries in a whitelist"""
        if list_type not in self.whitelists or list_id not in self.whitelists[list_type]:
            return []
        
        entries = self.whitelists[list_type][list_id]
        if not include_disabled:
            entries = [e for e in entries if e.enabled and not e.is_expired()]
        
        return [e.to_dict() for e in entries]
    
    def list_whitelists(self) -> Dict[str, Dict]:
        """List all whitelists with entry counts"""
        result = {}
        for list_type in self.whitelists:
            result[list_type] = {}
            for list_id, entries in self.whitelists[list_type].items():
                active_count = sum(1 for e in entries if e.enabled and not e.is_expired())
                result[list_type][list_id] = {
                    "total_entries": len(entries),
                    "active_entries": active_count
                }
        return result
    
    def check_matches(
        self,
        text: str,
        *,
        global_list: bool = True,
        profile: Optional[str] = None,
        organization: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """
        Check if text matches any whitelisted patterns
        
        Returns:
            (is_whitelisted, matching_patterns)
        """
        matched_patterns = []
        
        # Check global
        if global_list:
            for entry in self.whitelists[WhitelistType.GLOBAL.value].get("default", []):
                if entry.matches(text):
                    matched_patterns.append(entry.pattern)
        
        # Check profile
        if profile:
            for entry in self.whitelists[WhitelistType.PROFILE.value].get(profile, []):
                if entry.matches(text):
                    matched_patterns.append(entry.pattern)
        
        # Check organization
        if organization:
            for entry in self.whitelists[WhitelistType.ORGANIZATION.value].get(organization, []):
                if entry.matches(text):
                    matched_patterns.append(entry.pattern)
        
        # Check temporary
        for entry in self.whitelists[WhitelistType.TEMPORARY.value].get("session", []):
            if entry.matches(text):
                matched_patterns.append(entry.pattern)
        
        return len(matched_patterns) > 0, matched_patterns
    
    def _audit_log(self, action: str, list_type: str, list_id: str, pattern: str, user: str):
        """Log audit entry"""
        try:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "action": action,
                "list_type": list_type,
                "list_id": list_id,
                "pattern": pattern[:50],  # Truncate long patterns
                "user": user
            }
            
            with open(self.audit_log_file, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"Error writing audit log: {e}")
    
    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        """Get recent audit log entries"""
        entries = []
        try:
            if self.audit_log_file.exists():
                with open(self.audit_log_file, 'r') as f:
                    lines = f.readlines()[-limit:]
                    for line in lines:
                        try:
                            entries.append(json.loads(line))
                        except:
                            pass
        except Exception as e:
            print(f"Error reading audit log: {e}")
        
        return entries


# Singleton instance
_manager = None

def get_whitelist_manager(data_dir: str = "data") -> WhitelistManager:
    """Get or create the whitelist manager singleton"""
    global _manager
    if _manager is None:
        _manager = WhitelistManager(data_dir)
    return _manager
