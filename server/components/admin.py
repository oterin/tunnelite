import os
from typing import List, Optional

from fastapi import (
    APIRouter,
    Security,
    HTTPException,
    status,
    Depends,
    Request
)

from fastapi.security import APIKeyHeader

from server.components import database
from server.components.models import *
from pydantic import BaseModel, Field
from server import config

from .auth import get_admin_user
from .models import BanType, BanScope, BanTarget, Ban, BanCheck
from .bans import (
    create_ban, check_ban, list_bans, remove_ban, kick_user, 
    get_ban_stats, get_client_ip
)
from .database import get_value, set_value



# load config from values.json or env
ADMIN_API_KEY = config.get("TUNNELITE_ADMIN_KEY")
if not ADMIN_API_KEY:
    raise ValueError("TUNNELITE_ADMIN_KEY not configured")

api_key_header = APIKeyHeader(
    name="X-Admin-Key",
    auto_error=False
)

async def get_admin_api_key(
    key: str = Security(api_key_header)
):
    if key == ADMIN_API_KEY:
        return key
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or missing admin key"
    )

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(get_admin_api_key)]
)

@router.get("/nodes", response_model=List[Node])
async def list_all_nodes():
    return database.get_all_nodes()

@router.get("/nodes/pending", response_model=List[Node])
async def list_pending_nodes():
    """returns a list of all nodes with 'pending' status."""
    all_nodes = database.get_all_nodes()
    return [node for node in all_nodes if node.get("status") == "pending"]

@router.post(
    "/nodes/{node_secret_id}/approve",
    status_code=status.HTTP_200_OK,
    summary="Approve a pending node"
)
async def approve_node(node_secret_id: str) -> dict:
    """approves a node, changing its status from 'pending' to 'active'."""
    node = database.get_node_by_secret_id(node_secret_id)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="node not found"
        )
    
    if node.get("status") != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"node is not in 'pending' state (current state: {node.get('status')})"
        )

    if database.update_node_status(node["node_secret_id"], "active"):
        return {
            "message": f"node with secret id '{node_secret_id[:8]}...' has been approved and is now active."
        }

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="failed to approve node"
    )

@router.post(
    "/nodes/{node_secret_id}/disable",
    status_code=status.HTTP_200_OK,
    summary="Disable an active node"
)
async def disable_node(node_secret_id: str) -> dict:
    """disables a node, changing its status to 'disabled'."""
    node = database.get_node_by_secret_id(node_secret_id)
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="node not found"
        )

    if database.update_node_status(node["node_secret_id"], "disabled"):
        return {
            "message": f"node '{node.get('public_hostname', node_secret_id[:8])}' disabled"
        }

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="failed to disable node"
    )

# ban management endpoints

@router.post("/bans/create")
async def create_ban_endpoint(
    request: Request,
    ban_type: BanType,
    ban_scope: BanScope,
    ban_target: BanTarget,
    reason: str,
    target_ip: Optional[str] = None,
    target_username: Optional[str] = None,
    target_user_id: Optional[str] = None,
    tunnel_id: Optional[str] = None,
    node_id: Optional[str] = None,
    duration_minutes: Optional[int] = None,
    notes: Optional[str] = None,
    admin_user: dict = Depends(get_admin_user)
):
    """create a new ban"""
    try:
        ban = create_ban(
            ban_type=ban_type,
            ban_scope=ban_scope,
            ban_target=ban_target,
            reason=reason,
            banned_by=admin_user["username"],
            target_ip=target_ip,
            target_username=target_username,
            target_user_id=target_user_id,
            tunnel_id=tunnel_id,
            node_id=node_id,
            duration_minutes=duration_minutes,
            notes=notes
        )
        
        return {
            "status": "success",
            "message": f"ban created successfully",
            "ban_id": ban.id,
            "ban": ban.dict()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to create ban: {e}")

@router.post("/bans/kick")
async def kick_user_endpoint(
    request: Request,
    ip_address: Optional[str] = None,
    username: Optional[str] = None,
    user_id: Optional[str] = None,
    tunnel_id: Optional[str] = None,
    node_id: Optional[str] = None,
    reason: str = "kicked by admin",
    admin_user: dict = Depends(get_admin_user)
):
    """kick a user (immediate disconnect without persistent ban)"""
    
    # if no ip provided, try to get from request
    if not ip_address:
        ip_address = get_client_ip(request)
    
    if not any([ip_address, username, user_id]):
        raise HTTPException(status_code=400, detail="must specify at least one target (ip, username, or user_id)")
    
    try:
        success = kick_user(
            ip_address=ip_address or "unknown",
            username=username,
            user_id=user_id,
            tunnel_id=tunnel_id,
            node_id=node_id,
            reason=reason,
            kicked_by=admin_user["username"]
        )
        
        if success:
            return {
                "status": "success",
                "message": "user kicked successfully",
                "action": "kick",
                "target": {
                    "ip_address": ip_address,
                    "username": username,
                    "user_id": user_id,
                    "tunnel_id": tunnel_id,
                    "node_id": node_id
                }
            }
        else:
            raise HTTPException(status_code=500, detail="failed to kick user")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to kick user: {e}")

@router.post("/bans/tempban")
async def create_tempban_endpoint(
    request: Request,
    ban_scope: BanScope,
    ban_target: BanTarget,
    reason: str,
    duration_minutes: int,
    target_ip: Optional[str] = None,
    target_username: Optional[str] = None,
    target_user_id: Optional[str] = None,
    tunnel_id: Optional[str] = None,
    node_id: Optional[str] = None,
    notes: Optional[str] = None,
    admin_user: dict = Depends(get_admin_user)
):
    """create a temporary ban"""
    
    if duration_minutes <= 0:
        raise HTTPException(status_code=400, detail="duration must be positive")
    
    if duration_minutes > 525600:  # 1 year max
        raise HTTPException(status_code=400, detail="duration cannot exceed 1 year")
    
    try:
        ban = create_ban(
            ban_type=BanType.TEMPBAN,
            ban_scope=ban_scope,
            ban_target=ban_target,
            reason=reason,
            banned_by=admin_user["username"],
            target_ip=target_ip,
            target_username=target_username,
            target_user_id=target_user_id,
            tunnel_id=tunnel_id,
            node_id=node_id,
            duration_minutes=duration_minutes,
            notes=notes
        )
        
        return {
            "status": "success",
            "message": f"temporary ban created for {duration_minutes} minutes",
            "ban_id": ban.id,
            "expires_at": ban.expires_at.isoformat() if ban.expires_at else None,
            "ban": ban.dict()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to create tempban: {e}")

@router.post("/bans/permban")
async def create_permban_endpoint(
    request: Request,
    ban_scope: BanScope,
    ban_target: BanTarget,
    reason: str,
    target_ip: Optional[str] = None,
    target_username: Optional[str] = None,
    target_user_id: Optional[str] = None,
    tunnel_id: Optional[str] = None,
    node_id: Optional[str] = None,
    notes: Optional[str] = None,
    admin_user: dict = Depends(get_admin_user)
):
    """create a permanent ban"""
    
    try:
        ban = create_ban(
            ban_type=BanType.PERMBAN,
            ban_scope=ban_scope,
            ban_target=ban_target,
            reason=reason,
            banned_by=admin_user["username"],
            target_ip=target_ip,
            target_username=target_username,
            target_user_id=target_user_id,
            tunnel_id=tunnel_id,
            node_id=node_id,
            notes=notes
        )
        
        return {
            "status": "success",
            "message": "permanent ban created",
            "ban_id": ban.id,
            "ban": ban.dict()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to create permban: {e}")

@router.get("/bans/list")
async def list_bans_endpoint(
    scope: Optional[BanScope] = None,
    target: Optional[BanTarget] = None,
    active_only: bool = True,
    limit: int = 100,
    offset: int = 0,
    admin_user: dict = Depends(get_admin_user)
):
    """list bans with optional filtering"""
    
    if limit > 500:
        raise HTTPException(status_code=400, detail="limit cannot exceed 500")
    
    try:
        bans = list_bans(
            scope=scope,
            target=target,
            active_only=active_only,
            limit=limit,
            offset=offset
        )
        
        return {
            "status": "success",
            "bans": [ban.dict() for ban in bans],
            "count": len(bans),
            "filters": {
                "scope": scope.value if scope else None,
                "target": target.value if target else None,
                "active_only": active_only
            },
            "pagination": {
                "limit": limit,
                "offset": offset
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to list bans: {e}")

@router.delete("/bans/{ban_id}")
async def remove_ban_endpoint(
    ban_id: str,
    admin_user: dict = Depends(get_admin_user)
):
    """remove/deactivate a ban"""
    
    try:
        success = remove_ban(ban_id, admin_user["username"])
        
        if success:
            return {
                "status": "success",
                "message": "ban removed successfully",
                "ban_id": ban_id
            }
        else:
            raise HTTPException(status_code=404, detail="ban not found or already inactive")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to remove ban: {e}")

@router.post("/bans/check")
async def check_ban_endpoint(
    request: Request,
    ip_address: Optional[str] = None,
    username: Optional[str] = None,
    user_id: Optional[str] = None,
    tunnel_id: Optional[str] = None,
    node_id: Optional[str] = None,
    admin_user: dict = Depends(get_admin_user)
):
    """check if ip/user is banned"""
    
    # if no ip provided, use request ip
    if not ip_address:
        ip_address = get_client_ip(request)
    
    if not any([ip_address, username, user_id]):
        raise HTTPException(status_code=400, detail="must specify at least one target")
    
    try:
        ban_check = check_ban(
            ip_address=ip_address or "unknown",
            username=username,
            user_id=user_id,
            tunnel_id=tunnel_id,
            node_id=node_id
        )
        
        return {
            "status": "success",
            "ban_check": ban_check.dict(),
            "target": {
                "ip_address": ip_address,
                "username": username,
                "user_id": user_id,
                "tunnel_id": tunnel_id,
                "node_id": node_id
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to check ban: {e}")

@router.get("/bans/stats")
async def get_ban_stats_endpoint(admin_user: dict = Depends(get_admin_user)):
    """get ban statistics"""
    
    try:
        stats = get_ban_stats()
        
        return {
            "status": "success",
            "stats": stats,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to get ban stats: {e}")

# bulk ban operations

@router.post("/bans/bulk/ip-range")
async def bulk_ban_ip_range_endpoint(
    request: Request,
    ip_range: str,  # e.g., "192.168.1.0/24" or "192.168.1.1-192.168.1.100"
    ban_type: BanType,
    ban_scope: BanScope,
    reason: str,
    duration_minutes: Optional[int] = None,
    notes: Optional[str] = None,
    admin_user: dict = Depends(get_admin_user)
):
    """bulk ban an ip range"""
    
    # todo: implement ip range parsing and bulk ban logic
    # this would parse the ip range and create individual bans for each ip
    
    return {
        "status": "error",
        "message": "bulk ip range bans not yet implemented"
    }

@router.post("/bans/bulk/users")
async def bulk_ban_users_endpoint(
    request: Request,
    usernames: List[str],
    ban_type: BanType,
    ban_scope: BanScope,
    reason: str,
    duration_minutes: Optional[int] = None,
    notes: Optional[str] = None,
    admin_user: dict = Depends(get_admin_user)
):
    """bulk ban multiple users"""
    
    if len(usernames) > 100:
        raise HTTPException(status_code=400, detail="cannot ban more than 100 users at once")
    
    results = []
    for username in usernames:
        try:
            ban = create_ban(
                ban_type=ban_type,
                ban_scope=ban_scope,
                ban_target=BanTarget.ACCOUNT,
                reason=reason,
                banned_by=admin_user["username"],
                target_username=username,
                duration_minutes=duration_minutes,
                notes=notes
            )
            results.append({
                "username": username,
                "status": "success",
                "ban_id": ban.id
            })
        except Exception as e:
            results.append({
                "username": username,
                "status": "error",
                "error": str(e)
            })
    
    success_count = sum(1 for r in results if r["status"] == "success")
    
    return {
        "status": "success" if success_count == len(usernames) else "partial",
        "message": f"banned {success_count}/{len(usernames)} users",
        "results": results
    }

# moderation log endpoints

@router.get("/moderation/log")
async def get_moderation_log_endpoint(
    limit: int = 100,
    offset: int = 0,
    admin_user: dict = Depends(get_admin_user)
):
    """get moderation log entries"""
    
    if limit > 500:
        raise HTTPException(status_code=400, detail="limit cannot exceed 500")
    
    try:
        mod_logs = get_value("moderation_log_index", [])
        
        # apply pagination
        start_idx = offset
        end_idx = offset + limit
        paginated_log_ids = mod_logs[start_idx:end_idx]
        
        # get log entries
        log_entries = []
        for log_id in paginated_log_ids:
            log_data = get_value(f"moderation_log:{log_id}")
            if log_data:
                log_entries.append(log_data)
        
        return {
            "status": "success",
            "log_entries": log_entries,
            "count": len(log_entries),
            "total": len(mod_logs),
            "pagination": {
                "limit": limit,
                "offset": offset
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to get moderation log: {e}")

@router.post("/moderation/log")
async def get_moderation_log(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    admin_user: dict = Depends(get_admin_user)
):
    """get moderation action log"""
    try:
        # get moderation log entries
        log_index = get_value("moderation_log_index", [])
        
        # paginate
        start_idx = max(0, len(log_index) - offset - limit)
        end_idx = len(log_index) - offset
        selected_log_ids = log_index[start_idx:end_idx]
        
        # get log entries
        log_entries = []
        for log_id in reversed(selected_log_ids):  # most recent first
            log_entry = get_value(f"moderation_log:{log_id}")
            if log_entry:
                log_entries.append(log_entry)
        
        return {
            "status": "success",
            "log_entries": log_entries,
            "total_entries": len(log_index),
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to get moderation log: {e}")

# node owner ban management endpoints
@router.post("/nodes/{node_id}/bans/create")
async def create_node_ban(
    request: Request,
    node_id: str,
    ban_type: BanType,
    ban_target: BanTarget,
    reason: str,
    target_ip: Optional[str] = None,
    target_username: Optional[str] = None,
    target_user_id: Optional[str] = None,
    duration_minutes: Optional[int] = None,
    notes: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """create a ban for a specific node (node owners only)"""
    try:
        # verify node ownership
        node = database.get_node_by_secret_id(node_id)
        if not node:
            raise HTTPException(status_code=404, detail="node not found")
        
        if node.get("owner_username") != current_user["username"]:
            raise HTTPException(status_code=403, detail="you can only manage bans for your own nodes")
        
        # create the ban
        ban = create_ban(
            ban_type=ban_type,
            ban_scope=BanScope.NODE,
            ban_target=ban_target,
            reason=reason,
            banned_by=current_user["username"],
            target_ip=target_ip,
            target_username=target_username,
            target_user_id=target_user_id,
            node_id=node_id,
            duration_minutes=duration_minutes,
            notes=notes
        )
        
        return {
            "status": "success",
            "message": f"ban created successfully",
            "ban_id": ban.id,
            "ban": ban.dict()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to create ban: {e}")

@router.post("/nodes/{node_id}/bans/kick")
async def kick_user_from_node(
    request: Request,
    node_id: str,
    ip_address: Optional[str] = None,
    username: Optional[str] = None,
    user_id: Optional[str] = None,
    reason: str = "kicked by node owner",
    current_user: dict = Depends(get_current_user)
):
    """kick a user from a specific node (node owners only)"""
    try:
        # verify node ownership
        node = database.get_node_by_secret_id(node_id)
        if not node:
            raise HTTPException(status_code=404, detail="node not found")
        
        if node.get("owner_username") != current_user["username"]:
            raise HTTPException(status_code=403, detail="you can only kick users from your own nodes")
        
        # if no ip provided, try to get from request
        if not ip_address:
            ip_address = get_client_ip(request)
        
        if not any([ip_address, username, user_id]):
            raise HTTPException(status_code=400, detail="must specify at least one target (ip, username, or user_id)")
        
        success = kick_user(
            ip_address=ip_address or "unknown",
            username=username,
            user_id=user_id,
            node_id=node_id,
            reason=reason,
            kicked_by=current_user["username"]
        )
        
        if success:
            return {
                "status": "success",
                "message": "user kicked successfully",
                "action": "kick",
                "target": {
                    "ip_address": ip_address,
                    "username": username,
                    "user_id": user_id,
                    "node_id": node_id
                }
            }
        else:
            raise HTTPException(status_code=500, detail="failed to kick user")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to kick user: {e}")

@router.post("/nodes/{node_id}/bans/list")
async def list_node_bans(
    request: Request,
    node_id: str,
    active_only: bool = True,
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """list bans for a specific node (node owners only)"""
    try:
        # verify node ownership
        node = database.get_node_by_secret_id(node_id)
        if not node:
            raise HTTPException(status_code=404, detail="node not found")
        
        if node.get("owner_username") != current_user["username"]:
            raise HTTPException(status_code=403, detail="you can only view bans for your own nodes")
        
        # get bans for this node
        bans = list_bans(
            scope=BanScope.NODE,
            active_only=active_only,
            limit=limit,
            offset=offset
        )
        
        # filter to only this node
        node_bans = [ban for ban in bans if ban.node_id == node_id]
        
        return {
            "status": "success",
            "bans": [ban.dict() for ban in node_bans],
            "node_hostname": node.get("public_hostname"),
            "total_bans": len(node_bans),
            "active_only": active_only
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to list bans: {e}")

@router.delete("/nodes/{node_id}/bans/{ban_id}")
async def remove_node_ban(
    request: Request,
    node_id: str,
    ban_id: str,
    current_user: dict = Depends(get_current_user)
):
    """remove a ban from a specific node (node owners only)"""
    try:
        # verify node ownership
        node = database.get_node_by_secret_id(node_id)
        if not node:
            raise HTTPException(status_code=404, detail="node not found")
        
        if node.get("owner_username") != current_user["username"]:
            raise HTTPException(status_code=403, detail="you can only remove bans from your own nodes")
        
        # verify ban belongs to this node
        ban_data = get_value(f"ban:{ban_id}")
        if not ban_data:
            raise HTTPException(status_code=404, detail="ban not found")
        
        if ban_data.get("node_id") != node_id:
            raise HTTPException(status_code=403, detail="ban does not belong to your node")
        
        # remove the ban
        success = remove_ban(ban_id, current_user["username"])
        
        if success:
            return {
                "status": "success",
                "message": "ban removed successfully",
                "ban_id": ban_id
            }
        else:
            raise HTTPException(status_code=500, detail="failed to remove ban")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to remove ban: {e}")

# tunnel owner ban management endpoints
@router.post("/tunnels/{tunnel_id}/bans/create")
async def create_tunnel_ban(
    request: Request,
    tunnel_id: str,
    ban_type: BanType,
    ban_target: BanTarget,
    reason: str,
    target_ip: Optional[str] = None,
    target_username: Optional[str] = None,
    target_user_id: Optional[str] = None,
    duration_minutes: Optional[int] = None,
    notes: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """create a ban for a specific tunnel (tunnel owners only)"""
    try:
        # verify tunnel ownership
        tunnel = database.get_tunnel_by_id(tunnel_id)
        if not tunnel:
            raise HTTPException(status_code=404, detail="tunnel not found")
        
        if tunnel.get("owner_username") != current_user["username"]:
            raise HTTPException(status_code=403, detail="you can only manage bans for your own tunnels")
        
        # create the ban
        ban = create_ban(
            ban_type=ban_type,
            ban_scope=BanScope.TUNNEL,
            ban_target=ban_target,
            reason=reason,
            banned_by=current_user["username"],
            target_ip=target_ip,
            target_username=target_username,
            target_user_id=target_user_id,
            tunnel_id=tunnel_id,
            duration_minutes=duration_minutes,
            notes=notes
        )
        
        return {
            "status": "success",
            "message": f"ban created successfully",
            "ban_id": ban.id,
            "ban": ban.dict()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to create ban: {e}")

@router.post("/tunnels/{tunnel_id}/bans/kick")
async def kick_user_from_tunnel(
    request: Request,
    tunnel_id: str,
    ip_address: Optional[str] = None,
    username: Optional[str] = None,
    user_id: Optional[str] = None,
    reason: str = "kicked by tunnel owner",
    current_user: dict = Depends(get_current_user)
):
    """kick a user from a specific tunnel (tunnel owners only)"""
    try:
        # verify tunnel ownership
        tunnel = database.get_tunnel_by_id(tunnel_id)
        if not tunnel:
            raise HTTPException(status_code=404, detail="tunnel not found")
        
        if tunnel.get("owner_username") != current_user["username"]:
            raise HTTPException(status_code=403, detail="you can only kick users from your own tunnels")
        
        # if no ip provided, try to get from request
        if not ip_address:
            ip_address = get_client_ip(request)
        
        if not any([ip_address, username, user_id]):
            raise HTTPException(status_code=400, detail="must specify at least one target (ip, username, or user_id)")
        
        success = kick_user(
            ip_address=ip_address or "unknown",
            username=username,
            user_id=user_id,
            tunnel_id=tunnel_id,
            reason=reason,
            kicked_by=current_user["username"]
        )
        
        if success:
            return {
                "status": "success",
                "message": "user kicked successfully",
                "action": "kick",
                "target": {
                    "ip_address": ip_address,
                    "username": username,
                    "user_id": user_id,
                    "tunnel_id": tunnel_id
                }
            }
        else:
            raise HTTPException(status_code=500, detail="failed to kick user")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to kick user: {e}")

@router.post("/tunnels/{tunnel_id}/bans/list")
async def list_tunnel_bans(
    request: Request,
    tunnel_id: str,
    active_only: bool = True,
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """list bans for a specific tunnel (tunnel owners only)"""
    try:
        # verify tunnel ownership
        tunnel = database.get_tunnel_by_id(tunnel_id)
        if not tunnel:
            raise HTTPException(status_code=404, detail="tunnel not found")
        
        if tunnel.get("owner_username") != current_user["username"]:
            raise HTTPException(status_code=403, detail="you can only view bans for your own tunnels")
        
        # get bans for this tunnel
        bans = list_bans(
            scope=BanScope.TUNNEL,
            active_only=active_only,
            limit=limit,
            offset=offset
        )
        
        # filter to only this tunnel
        tunnel_bans = [ban for ban in bans if ban.tunnel_id == tunnel_id]
        
        return {
            "status": "success",
            "bans": [ban.dict() for ban in tunnel_bans],
            "tunnel_url": tunnel.get("public_url"),
            "total_bans": len(tunnel_bans),
            "active_only": active_only
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to list bans: {e}")

@router.delete("/tunnels/{tunnel_id}/bans/{ban_id}")
async def remove_tunnel_ban(
    request: Request,
    tunnel_id: str,
    ban_id: str,
    current_user: dict = Depends(get_current_user)
):
    """remove a ban from a specific tunnel (tunnel owners only)"""
    try:
        # verify tunnel ownership
        tunnel = database.get_tunnel_by_id(tunnel_id)
        if not tunnel:
            raise HTTPException(status_code=404, detail="tunnel not found")
        
        if tunnel.get("owner_username") != current_user["username"]:
            raise HTTPException(status_code=403, detail="you can only remove bans from your own tunnels")
        
        # verify ban belongs to this tunnel
        ban_data = get_value(f"ban:{ban_id}")
        if not ban_data:
            raise HTTPException(status_code=404, detail="ban not found")
        
        if ban_data.get("tunnel_id") != tunnel_id:
            raise HTTPException(status_code=403, detail="ban does not belong to your tunnel")
        
        # remove the ban
        success = remove_ban(ban_id, current_user["username"])
        
        if success:
            return {
                "status": "success",
                "message": "ban removed successfully",
                "ban_id": ban_id
            }
        else:
            raise HTTPException(status_code=500, detail="failed to remove ban")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to remove ban: {e}")
