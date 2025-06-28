"""
ban management system for tunnelite
handles kicks, tempbans, and permanent bans at tunnel/node/service level
"""

import time
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import HTTPException
import ipaddress

from .models import Ban, BanType, BanScope, BanTarget, BanCheck
from .database import get_value, set_value, list_keys, delete_key

def get_client_ip(request) -> str:
    """extract client ip from request headers"""
    # check for forwarded headers first
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    
    # fallback to direct connection
    return request.client.host

def normalize_ip(ip_str: str) -> str:
    """normalize ip address for consistent storage"""
    try:
        # parse and normalize the ip
        ip = ipaddress.ip_address(ip_str)
        return str(ip)
    except ValueError:
        return ip_str  # return as-is if not valid ip

def create_ban(
    ban_type: BanType,
    ban_scope: BanScope, 
    ban_target: BanTarget,
    reason: str,
    banned_by: str,
    target_ip: Optional[str] = None,
    target_username: Optional[str] = None,
    target_user_id: Optional[str] = None,
    tunnel_id: Optional[str] = None,
    node_id: Optional[str] = None,
    duration_minutes: Optional[int] = None,
    notes: Optional[str] = None
) -> Ban:
    """create a new ban record"""
    
    # validate targets
    if ban_target in [BanTarget.IP, BanTarget.BOTH] and not target_ip:
        raise ValueError("target_ip required for ip-based bans")
    
    if ban_target in [BanTarget.ACCOUNT, BanTarget.BOTH] and not (target_username or target_user_id):
        raise ValueError("target_username or target_user_id required for account-based bans")
    
    # validate scope
    if ban_scope == BanScope.TUNNEL and not tunnel_id:
        raise ValueError("tunnel_id required for tunnel-scoped bans")
    
    if ban_scope == BanScope.NODE and not node_id:
        raise ValueError("node_id required for node-scoped bans")
    
    # calculate expiration
    expires_at = None
    if ban_type == BanType.TEMPBAN and duration_minutes:
        expires_at = datetime.utcnow() + timedelta(minutes=duration_minutes)
    
    # normalize ip if provided
    if target_ip:
        target_ip = normalize_ip(target_ip)
    
    # create ban record
    ban = Ban(
        id=f"ban_{int(time.time() * 1000)}_{hash(f'{target_ip}{target_username}{tunnel_id}{node_id}') % 10000}",
        ban_type=ban_type,
        ban_scope=ban_scope,
        ban_target=ban_target,
        target_ip=target_ip,
        target_username=target_username,
        target_user_id=target_user_id,
        tunnel_id=tunnel_id,
        node_id=node_id,
        reason=reason,
        banned_by=banned_by,
        banned_at=datetime.utcnow(),
        expires_at=expires_at,
        notes=notes
    )
    
    # store in key-value database
    ban_data = ban.dict()
    ban_data["banned_at"] = ban_data["banned_at"].isoformat()
    if ban_data["expires_at"]:
        ban_data["expires_at"] = ban_data["expires_at"].isoformat()
    ban_data["created_at"] = ban_data["created_at"].isoformat()
    ban_data["updated_at"] = ban_data["updated_at"].isoformat()
    
    # store ban record
    set_value(f"ban:{ban.id}", ban_data)
    
    # create indexes for efficient lookups
    if ban.target_ip:
        # add to ip index
        ip_bans = get_value(f"ban_index:ip:{ban.target_ip}", [])
        if ban.id not in ip_bans:
            ip_bans.append(ban.id)
            set_value(f"ban_index:ip:{ban.target_ip}", ip_bans)
    
    if ban.target_username:
        # add to username index
        user_bans = get_value(f"ban_index:user:{ban.target_username}", [])
        if ban.id not in user_bans:
            user_bans.append(ban.id)
            set_value(f"ban_index:user:{ban.target_username}", user_bans)
    
    if ban.tunnel_id:
        # add to tunnel index
        tunnel_bans = get_value(f"ban_index:tunnel:{ban.tunnel_id}", [])
        if ban.id not in tunnel_bans:
            tunnel_bans.append(ban.id)
            set_value(f"ban_index:tunnel:{ban.tunnel_id}", tunnel_bans)
    
    if ban.node_id:
        # add to node index
        node_bans = get_value(f"ban_index:node:{ban.node_id}", [])
        if ban.id not in node_bans:
            node_bans.append(ban.id)
            set_value(f"ban_index:node:{ban.node_id}", node_bans)
    
    # add to active bans index
    active_bans = get_value("ban_index:active", [])
    if ban.id not in active_bans:
        active_bans.append(ban.id)
        set_value("ban_index:active", active_bans)
    
    return ban

def check_ban(
    ip_address: str,
    username: Optional[str] = None,
    user_id: Optional[str] = None,
    tunnel_id: Optional[str] = None,
    node_id: Optional[str] = None
) -> BanCheck:
    """check if ip/user is banned at any relevant scope"""
    
    ip_address = normalize_ip(ip_address)
    current_time = datetime.utcnow()
    
    # cleanup expired bans first
    _cleanup_expired_bans()
    
    # collect potential ban ids to check
    ban_ids_to_check = set()
    
    # get bans by ip
    if ip_address:
        ip_bans = get_value(f"ban_index:ip:{ip_address}", [])
        ban_ids_to_check.update(ip_bans)
    
    # get bans by username
    if username:
        user_bans = get_value(f"ban_index:user:{username}", [])
        ban_ids_to_check.update(user_bans)
    
    # get bans by tunnel
    if tunnel_id:
        tunnel_bans = get_value(f"ban_index:tunnel:{tunnel_id}", [])
        ban_ids_to_check.update(tunnel_bans)
    
    # get bans by node
    if node_id:
        node_bans = get_value(f"ban_index:node:{node_id}", [])
        ban_ids_to_check.update(node_bans)
    
    # check each potential ban
    active_bans = []
    
    for ban_id in ban_ids_to_check:
        ban_data = get_value(f"ban:{ban_id}")
        if not ban_data or not ban_data.get("is_active"):
            continue
        
        # check if ban applies to current context
        ban_applies = False
        
        # check target match
        target = ban_data.get("ban_target")
        if target == "ip" and ban_data.get("target_ip") == ip_address:
            ban_applies = True
        elif target == "account" and (
            (username and ban_data.get("target_username") == username) or
            (user_id and ban_data.get("target_user_id") == user_id)
        ):
            ban_applies = True
        elif target == "both" and (
            ban_data.get("target_ip") == ip_address or
            (username and ban_data.get("target_username") == username) or
            (user_id and ban_data.get("target_user_id") == user_id)
        ):
            ban_applies = True
        
        if not ban_applies:
            continue
        
        # check scope match
        scope = ban_data.get("ban_scope")
        if scope == "service":
            # service bans apply everywhere
            ban_applies = True
        elif scope == "node" and node_id and ban_data.get("node_id") == node_id:
            ban_applies = True
        elif scope == "tunnel" and tunnel_id and ban_data.get("tunnel_id") == tunnel_id:
            ban_applies = True
        elif scope in ["node", "tunnel"] and ban_data.get(f"{scope}_id") != locals().get(f"{scope}_id"):
            ban_applies = False
        
        if ban_applies:
            active_bans.append(ban_data)
    
    if not active_bans:
        return BanCheck(is_banned=False)
    
    # return the most recent/severe ban
    # priority: service > node > tunnel, then by ban type, then by date
    def ban_priority(ban):
        scope_priority = {"service": 3, "node": 2, "tunnel": 1}
        type_priority = {"permban": 3, "tempban": 2, "kick": 1}
        return (
            scope_priority.get(ban.get("ban_scope", ""), 0),
            type_priority.get(ban.get("ban_type", ""), 0),
            ban.get("banned_at", "")
        )
    
    most_severe_ban = max(active_bans, key=ban_priority)
    return _create_ban_check_result(most_severe_ban)

def _cleanup_expired_bans():
    """cleanup expired bans by deactivating them"""
    current_time = datetime.utcnow()
    active_bans = get_value("ban_index:active", [])
    
    for ban_id in active_bans[:]:  # copy list to avoid modification during iteration
        ban_data = get_value(f"ban:{ban_id}")
        if not ban_data:
            # remove from active index if ban doesn't exist
            active_bans.remove(ban_id)
            continue
        
        expires_at = ban_data.get("expires_at")
        if expires_at and datetime.fromisoformat(expires_at) < current_time:
            # deactivate expired ban
            ban_data["is_active"] = False
            ban_data["updated_at"] = current_time.isoformat()
            set_value(f"ban:{ban_id}", ban_data)
            
            # remove from active index
            active_bans.remove(ban_id)
    
    # update active bans index
    set_value("ban_index:active", active_bans)

def _create_ban_check_result(ban_data) -> BanCheck:
    """create ban check result from ban data"""
    expires_at = None
    if ban_data.get("expires_at"):
        expires_at = datetime.fromisoformat(ban_data["expires_at"])
    
    return BanCheck(
        is_banned=True,
        ban_type=BanType(ban_data["ban_type"]),
        ban_scope=BanScope(ban_data["ban_scope"]),
        reason=ban_data["reason"],
        expires_at=expires_at,
        banned_by=ban_data["banned_by"]
    )

def list_bans(
    scope: Optional[BanScope] = None,
    target: Optional[BanTarget] = None,
    active_only: bool = True,
    limit: int = 100,
    offset: int = 0
) -> List[Ban]:
    """list bans with optional filtering"""
    
    # cleanup expired bans first
    _cleanup_expired_bans()
    
    # get all ban keys
    ban_keys = [key for key in list_keys() if key.startswith("ban:") and not key.startswith("ban_index:")]
    
    bans = []
    for key in ban_keys:
        ban_data = get_value(key)
        if not ban_data:
            continue
        
        # apply filters
        if active_only and not ban_data.get("is_active", True):
            continue
        
        if scope and ban_data.get("ban_scope") != scope.value:
            continue
        
        if target and ban_data.get("ban_target") != target.value:
            continue
        
        # convert string dates back to datetime objects
        ban_data["banned_at"] = datetime.fromisoformat(ban_data["banned_at"])
        if ban_data.get("expires_at"):
            ban_data["expires_at"] = datetime.fromisoformat(ban_data["expires_at"])
        ban_data["created_at"] = datetime.fromisoformat(ban_data["created_at"])
        ban_data["updated_at"] = datetime.fromisoformat(ban_data["updated_at"])
        
        # convert string enums back to enum objects
        ban_data["ban_type"] = BanType(ban_data["ban_type"])
        ban_data["ban_scope"] = BanScope(ban_data["ban_scope"])
        ban_data["ban_target"] = BanTarget(ban_data["ban_target"])
        
        bans.append(Ban(**ban_data))
    
    # sort by banned_at descending
    bans.sort(key=lambda x: x.banned_at, reverse=True)
    
    # apply pagination
    start_idx = offset
    end_idx = offset + limit
    return bans[start_idx:end_idx]

def remove_ban(ban_id: str, removed_by: str) -> bool:
    """remove/deactivate a ban"""
    
    ban_data = get_value(f"ban:{ban_id}")
    if not ban_data or not ban_data.get("is_active"):
        return False
    
    # deactivate ban
    ban_data["is_active"] = False
    ban_data["updated_at"] = datetime.utcnow().isoformat()
    ban_data["notes"] = (ban_data.get("notes", "") + 
                        f"\nRemoved by {removed_by} at {datetime.utcnow().isoformat()}")
    
    set_value(f"ban:{ban_id}", ban_data)
    
    # remove from active bans index
    active_bans = get_value("ban_index:active", [])
    if ban_id in active_bans:
        active_bans.remove(ban_id)
        set_value("ban_index:active", active_bans)
    
    return True

def kick_user(
    ip_address: str,
    username: Optional[str] = None,
    user_id: Optional[str] = None,
    tunnel_id: Optional[str] = None,
    node_id: Optional[str] = None,
    reason: str = "kicked by admin",
    kicked_by: str = "system"
) -> bool:
    """immediately disconnect user (kick) - no persistent ban"""
    
    # kicks are implemented by triggering disconnect mechanisms
    # this is mainly for logging purposes and immediate action
    
    # log the kick action
    kick_log = {
        "action": "kick",
        "ip_address": normalize_ip(ip_address),
        "username": username,
        "user_id": user_id,
        "tunnel_id": tunnel_id,
        "node_id": node_id,
        "reason": reason,
        "kicked_by": kicked_by,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # store in moderation log
    log_id = f"modlog_{int(time.time() * 1000)}_{hash(f'{ip_address}{username}') % 10000}"
    set_value(f"moderation_log:{log_id}", kick_log)
    
    # add to moderation log index
    mod_logs = get_value("moderation_log_index", [])
    mod_logs.append(log_id)
    # keep only last 1000 entries
    if len(mod_logs) > 1000:
        # remove oldest entries
        for old_log_id in mod_logs[:-1000]:
            delete_key(f"moderation_log:{old_log_id}")
        mod_logs = mod_logs[-1000:]
    set_value("moderation_log_index", mod_logs)
    
    # todo: implement actual disconnection mechanism
    # this would need to integrate with the websocket/connection management
    
    return True

def get_ban_stats() -> Dict[str, Any]:
    """get statistics about active bans"""
    
    # cleanup expired bans first
    _cleanup_expired_bans()
    
    stats = {}
    active_bans = get_value("ban_index:active", [])
    
    # total active bans
    stats["total_active"] = len(active_bans)
    
    # collect ban data for analysis
    ban_data_list = []
    for ban_id in active_bans:
        ban_data = get_value(f"ban:{ban_id}")
        if ban_data:
            ban_data_list.append(ban_data)
    
    # by type
    type_counts = {}
    for ban_data in ban_data_list:
        ban_type = ban_data.get("ban_type", "unknown")
        type_counts[ban_type] = type_counts.get(ban_type, 0) + 1
    stats["by_type"] = type_counts
    
    # by scope
    scope_counts = {}
    for ban_data in ban_data_list:
        ban_scope = ban_data.get("ban_scope", "unknown")
        scope_counts[ban_scope] = scope_counts.get(ban_scope, 0) + 1
    stats["by_scope"] = scope_counts
    
    # by target
    target_counts = {}
    for ban_data in ban_data_list:
        ban_target = ban_data.get("ban_target", "unknown")
        target_counts[ban_target] = target_counts.get(ban_target, 0) + 1
    stats["by_target"] = target_counts
    
    # recent activity (last 24 hours)
    recent_time = datetime.utcnow() - timedelta(hours=24)
    recent_count = 0
    for ban_data in ban_data_list:
        banned_at_str = ban_data.get("banned_at")
        if banned_at_str:
            banned_at = datetime.fromisoformat(banned_at_str)
            if banned_at > recent_time:
                recent_count += 1
    stats["recent_bans"] = recent_count
    
    # expiring soon (next 24 hours)
    expire_time = datetime.utcnow() + timedelta(hours=24)
    expiring_count = 0
    for ban_data in ban_data_list:
        expires_at_str = ban_data.get("expires_at")
        if expires_at_str:
            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at < expire_time:
                expiring_count += 1
    stats["expiring_soon"] = expiring_count
    
    return stats 