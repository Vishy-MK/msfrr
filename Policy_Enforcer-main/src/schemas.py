from pydantic import BaseModel, Field
from typing import List, Optional, Literal

class Metadata(BaseModel):
    user_id: str
    risk_score: int
    categories: List[str]
    org_policy_profile: str
    compliance_profile: List[str]

class EnforceRequest(BaseModel):
    mode: Literal["INPUT", "OUTPUT"]
    content: str
    metadata: Metadata
    whitelist: Optional[List[str]] = Field(
        default=None, 
        description="List of literal strings or regex patterns to NOT redact. Examples: ['my_api_key_123', 'user@example.com', 'sk_test_.*']"
    )

class EnforceResponse(BaseModel):
    sanitized_content: str
    blocked: bool
    modifications: List[str]
    compliance_flags: List[str]


# ============================================================================
# Whitelist Management Schemas
# ============================================================================

class AddWhitelistEntryRequest(BaseModel):
    """Add entry to whitelist"""
    pattern: str = Field(..., description="Text pattern or regex to whitelist")
    description: Optional[str] = Field(default="", description="Description of why this is whitelisted")
    entry_type: Literal["EXACT", "REGEX"] = Field(default="EXACT", description="Match type")
    expires_at: Optional[str] = Field(default=None, description="ISO format expiration date")
    tags: Optional[List[str]] = Field(default=None, description="Tags for organization")


class WhitelistEntryResponse(BaseModel):
    """Response for whitelist entry"""
    pattern: str
    description: str
    type: str
    created_by: str
    created_at: str
    expires_at: Optional[str]
    tags: List[str]
    enabled: bool
    hash: str


class WhitelistListResponse(BaseModel):
    """Response for listing whitelist entries"""
    total_entries: int
    active_entries: int
    entries: List[WhitelistEntryResponse]


class AuditLogEntry(BaseModel):
    """Audit log entry"""
    timestamp: str
    action: str
    list_type: str
    list_id: str
    pattern: str
    user: str


class WhitelistStatusResponse(BaseModel):
    """Status of all whitelists"""
    whitelists: dict
    total_entries: int
    active_entries: int


class RemoveWhitelistEntryRequest(BaseModel):
    """Remove entry from whitelist"""
    pattern: str = Field(..., description="Pattern to remove")


class ToggleWhitelistEntryRequest(BaseModel):
    """Enable/disable whitelist entry"""
    pattern: str = Field(..., description="Pattern to toggle")
    enabled: bool = Field(..., description="Enable or disable")
