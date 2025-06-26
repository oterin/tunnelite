import asyncio
import time
from server.components import database
from server.logger import log

PENDING_STALE_THRESHOLD_SECONDS = 900  # 15 minutes
ACTIVE_STALE_THRESHOLD_SECONDS = 300   # 5 minutes

async def run_garbage_collection():
    log.info("running garbage collection for stale tunnels...")

    all_tunnels = database.get_all_tunnels()
    nodes_last_seen = {node['node_secret_id']: node.get("last_seen_at", 0) for node in database.get_all_nodes()}

    tunnels_to_close = []

    for tunnel in all_tunnels:
        status = tunnel.get("status")
        if status not in ["pending", "active"]:
            continue

        tunnel_id = tunnel.get("tunnel_id")
        if status == "pending" and time.time() - tunnel.get("created_at", 0) > PENDING_STALE_THRESHOLD_SECONDS:
            log.warning("found stale pending tunnel", extra={"tunnel_id": tunnel_id})
            tunnels_to_close.append(tunnel_id)

        elif status == "active":
            node_secret_id = tunnel.get("node_secret_id")
            last_seen = nodes_last_seen.get(node_secret_id, 0)
            if time.time() - last_seen > ACTIVE_STALE_THRESHOLD_SECONDS:
                log.warning("found tunnel on stale node", extra={"tunnel_id": tunnel_id, "node_secret_id": node_secret_id})
                tunnels_to_close.append(tunnel_id)

    if tunnels_to_close:
        for tunnel_id in tunnels_to_close:
            database.update_tunnel_status(tunnel_id, "closed_stale")
        log.info("garbage collection finished", extra={"tunnels_cleaned": len(tunnels_to_close)})
    else:
        log.info("garbage collection finished, no stale tunnels found.")

async def run_periodically(interval: int):
    while True:
        await run_garbage_collection()
        await asyncio.sleep(interval)
