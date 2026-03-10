from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from .schemas import (
    EnforceRequest, EnforceResponse,
    AddWhitelistEntryRequest, RemoveWhitelistEntryRequest,
    ToggleWhitelistEntryRequest, WhitelistListResponse,
    WhitelistStatusResponse, AuditLogEntry
)
from .engine import PolicyEnforcementEngine
from .whitelist_manager import get_whitelist_manager, WhitelistType
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SecureLLM Gateway - Policy Enforcement Module",
    description="Enterprise-grade policy enforcement with whitelist management",
    version="2.0"
)

engine = PolicyEnforcementEngine()
whitelist_mgr = get_whitelist_manager()

# ============================================================================
# POLICY ENFORCEMENT ENDPOINTS
# ============================================================================

@app.post("/enforce", response_model=EnforceResponse)
async def enforce_policy(request: EnforceRequest):
    """Enforce policy on content with optional whitelisting"""
    try:
        response = engine.enforce(request)
        return response
    except Exception as e:
        logger.error(f"Enforcement error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# WHITELIST MANAGEMENT ENDPOINTS
# ============================================================================

@app.post("/whitelist/global/add")
async def add_global_whitelist(request: AddWhitelistEntryRequest, user: str = "admin"):
    """Add entry to global whitelist"""
    try:
        success, message = whitelist_mgr.add_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern=request.pattern,
            description=request.description,
            entry_type=request.entry_type,
            created_by=user,
            expires_at=request.expires_at,
            tags=request.tags
        )
        
        if success:
            logger.info(f"Global whitelist entry added by {user}: {request.pattern}")
            return {"success": True, "message": message}
        else:
            raise HTTPException(status_code=400, detail=message)
    except Exception as e:
        logger.error(f"Error adding whitelist entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/whitelist/profile/{profile}/add")
async def add_profile_whitelist(profile: str, request: AddWhitelistEntryRequest, user: str = "admin"):
    """Add entry to profile-specific whitelist"""
    try:
        success, message = whitelist_mgr.add_entry(
            list_type=WhitelistType.PROFILE.value,
            list_id=profile,
            pattern=request.pattern,
            description=request.description,
            entry_type=request.entry_type,
            created_by=user,
            expires_at=request.expires_at,
            tags=request.tags
        )
        
        if success:
            logger.info(f"Profile whitelist ({profile}) entry added by {user}: {request.pattern}")
            return {"success": True, "message": message}
        else:
            raise HTTPException(status_code=400, detail=message)
    except Exception as e:
        logger.error(f"Error adding whitelist entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/whitelist/org/{org_id}/add")
async def add_org_whitelist(org_id: str, request: AddWhitelistEntryRequest, user: str = "admin"):
    """Add entry to organization-specific whitelist"""
    try:
        success, message = whitelist_mgr.add_entry(
            list_type=WhitelistType.ORGANIZATION.value,
            list_id=org_id,
            pattern=request.pattern,
            description=request.description,
            entry_type=request.entry_type,
            created_by=user,
            expires_at=request.expires_at,
            tags=request.tags
        )
        
        if success:
            logger.info(f"Org whitelist ({org_id}) entry added by {user}: {request.pattern}")
            return {"success": True, "message": message}
        else:
            raise HTTPException(status_code=400, detail=message)
    except Exception as e:
        logger.error(f"Error adding whitelist entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/whitelist/global/remove")
async def remove_global_whitelist(request: RemoveWhitelistEntryRequest, user: str = "admin"):
    """Remove entry from global whitelist"""
    try:
        success, message = whitelist_mgr.remove_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern=request.pattern,
            removed_by=user
        )
        
        if success:
            logger.info(f"Global whitelist entry removed by {user}: {request.pattern}")
            return {"success": True, "message": message}
        else:
            raise HTTPException(status_code=404, detail=message)
    except Exception as e:
        logger.error(f"Error removing whitelist entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/whitelist/profile/{profile}/remove")
async def remove_profile_whitelist(profile: str, request: RemoveWhitelistEntryRequest, user: str = "admin"):
    """Remove entry from profile whitelist"""
    try:
        success, message = whitelist_mgr.remove_entry(
            list_type=WhitelistType.PROFILE.value,
            list_id=profile,
            pattern=request.pattern,
            removed_by=user
        )
        
        if success:
            logger.info(f"Profile whitelist ({profile}) entry removed by {user}: {request.pattern}")
            return {"success": True, "message": message}
        else:
            raise HTTPException(status_code=404, detail=message)
    except Exception as e:
        logger.error(f"Error removing whitelist entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/whitelist/global/toggle")
async def toggle_global_whitelist(request: ToggleWhitelistEntryRequest, user: str = "admin"):
    """Enable/disable global whitelist entry"""
    try:
        success, message = whitelist_mgr.toggle_entry(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            pattern=request.pattern,
            enabled=request.enabled,
            toggled_by=user
        )
        
        if success:
            logger.info(f"Global whitelist entry toggled by {user}: {request.pattern}")
            return {"success": True, "message": message}
        else:
            raise HTTPException(status_code=404, detail=message)
    except Exception as e:
        logger.error(f"Error toggling whitelist entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/whitelist/profile/{profile}/toggle")
async def toggle_profile_whitelist(profile: str, request: ToggleWhitelistEntryRequest, user: str = "admin"):
    """Enable/disable profile whitelist entry"""
    try:
        success, message = whitelist_mgr.toggle_entry(
            list_type=WhitelistType.PROFILE.value,
            list_id=profile,
            pattern=request.pattern,
            enabled=request.enabled,
            toggled_by=user
        )
        
        if success:
            logger.info(f"Profile whitelist ({profile}) entry toggled by {user}: {request.pattern}")
            return {"success": True, "message": message}
        else:
            raise HTTPException(status_code=404, detail=message)
    except Exception as e:
        logger.error(f"Error toggling whitelist entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/whitelist/global/list", response_model=WhitelistListResponse)
async def list_global_whitelist(include_disabled: bool = False):
    """List global whitelist entries"""
    try:
        entries = whitelist_mgr.get_all_entries(
            list_type=WhitelistType.GLOBAL.value,
            list_id="default",
            include_disabled=include_disabled
        )
        return {
            "total_entries": len(whitelist_mgr.whitelists[WhitelistType.GLOBAL.value].get("default", [])),
            "active_entries": sum(1 for e in whitelist_mgr.whitelists[WhitelistType.GLOBAL.value].get("default", []) if e.enabled),
            "entries": entries
        }
    except Exception as e:
        logger.error(f"Error listing whitelist: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/whitelist/profile/{profile}/list", response_model=WhitelistListResponse)
async def list_profile_whitelist(profile: str, include_disabled: bool = False):
    """List profile-specific whitelist entries"""
    try:
        entries = whitelist_mgr.get_all_entries(
            list_type=WhitelistType.PROFILE.value,
            list_id=profile,
            include_disabled=include_disabled
        )
        profile_entries = whitelist_mgr.whitelists[WhitelistType.PROFILE.value].get(profile, [])
        return {
            "total_entries": len(profile_entries),
            "active_entries": sum(1 for e in profile_entries if e.enabled),
            "entries": entries
        }
    except Exception as e:
        logger.error(f"Error listing whitelist: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/whitelist/status", response_model=WhitelistStatusResponse)
async def whitelist_status():
    """Get overall whitelist status"""
    try:
        status = whitelist_mgr.list_whitelists()
        total = sum(v["total_entries"] for wl_type in status.values() for v in wl_type.values())
        active = sum(v["active_entries"] for wl_type in status.values() for v in wl_type.values())
        
        return {
            "whitelists": status,
            "total_entries": total,
            "active_entries": active
        }
    except Exception as e:
        logger.error(f"Error getting whitelist status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/whitelist/audit-log")
async def get_audit_log(limit: int = Query(100, ge=1, le=1000)):
    """Get whitelist audit log"""
    try:
        logs = whitelist_mgr.get_audit_log(limit)
        return {"entries": logs, "count": len(logs)}
    except Exception as e:
        logger.error(f"Error getting audit log: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# HEALTH & MONITORING ENDPOINTS
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "2.0",
        "features": ["policy_enforcement", "whitelist_management", "audit_logging"]
    }


@app.get("/")
async def root():
    """API documentation"""
    return {
        "name": "SecureLLM Gateway - Policy Enforcement Module",
        "version": "2.0",
        "documentation": "/docs",
        "endpoints": {
            "policy": {
                "enforce": "POST /enforce"
            },
            "whitelist": {
                "global": {
                    "add": "POST /whitelist/global/add",
                    "list": "GET /whitelist/global/list",
                    "remove": "DELETE /whitelist/global/remove",
                    "toggle": "PATCH /whitelist/global/toggle"
                },
                "profile": {
                    "add": "POST /whitelist/profile/{profile}/add",
                    "list": "GET /whitelist/profile/{profile}/list",
                    "remove": "DELETE /whitelist/profile/{profile}/remove",
                    "toggle": "PATCH /whitelist/profile/{profile}/toggle"
                },
                "org": {
                    "add": "POST /whitelist/org/{org_id}/add"
                },
                "status": "GET /whitelist/status",
                "audit": "GET /whitelist/audit-log"
            }
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
